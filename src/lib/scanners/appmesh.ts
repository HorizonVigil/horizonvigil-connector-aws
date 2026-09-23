import { createAwsClient } from '../awsApi';
import { fetchJson, reportWalk, walkPages, type PageWalk } from './restJson';
import { mapWithConcurrency, reportListingFailure } from './scannerSupport';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const APPMESH_RESOURCE_TYPES = ['app_mesh_mesh', 'app_mesh_virtual_node', 'app_mesh_virtual_service'] as const;

/** Meshes whose nodes/services are enumerated per run (two list walks each). */
const MAX_MESHES_ENUMERATED = 25;
const MESH_CONCURRENCY = 3;

interface MeshRef { meshName: string; arn?: string; meshOwner?: string; resourceOwner?: string; createdAt?: number | string }
interface VirtualNodeRef { virtualNodeName: string; arn?: string; meshName?: string; meshOwner?: string }
interface VirtualServiceRef { virtualServiceName: string; arn?: string; meshName?: string; meshOwner?: string }

/**
 * AWS App Mesh — REST-JSON, versioned path prefix /v20190125/.
 *
 * NOTE: AWS has announced end of support for App Mesh (30 September 2026).
 * Once the API stops answering, the failure is REPORTED, so existing rows
 * are not read as deletions; retiring these types is a catalog decision, not
 * something a scanner should do by returning nothing.
 *
 * What changed:
 *  - Every list paginates (nextToken). Previously page one only.
 *  - The mesh cap (was 10, silent) is now reported: nodes/services of meshes
 *    past the cap degrade coverage instead of being tombstoned.
 *  - Each mesh records its egress filter (DescribeMesh): ALLOW_ALL lets
 *    workloads reach any destination, DROP_ALL confines them to the mesh.
 */
export async function scanAppMesh(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'appmesh', ctx.region);
  const base = `https://appmesh.${ctx.region}.amazonaws.com/v20190125`;
  const list = <T>(path: string, key: string): Promise<PageWalk<T>> => walkPages<T>(
    (token) => fetchJson(client, `${base}${path}${path.includes('?') ? '&' : '?'}limit=100${token ? `&nextToken=${encodeURIComponent(token)}` : ''}`),
    (b) => b[key],
    (b) => b.nextToken,
  );

  const meshesWalk = await list<MeshRef>('/meshes', 'meshes');
  reportWalk(ctx, meshesWalk, 'appmesh', 'ListMeshes');
  const meshes = meshesWalk.items.filter((m) => !!m?.meshName);

  const out: ScannedResource[] = [];
  const enumerated = meshes.slice(0, MAX_MESHES_ENUMERATED);
  if (meshes.length > enumerated.length) {
    console.error(`App Mesh ${ctx.region}: ${meshes.length} meshes; nodes/services enumerated for the first ${enumerated.length}.`);
    reportListingFailure(ctx, { service: 'appmesh', action: 'ListVirtualNodes', region: ctx.region, truncated: true });
    reportListingFailure(ctx, { service: 'appmesh', action: 'ListVirtualServices', region: ctx.region, truncated: true });
  }

  const egress = new Map<string, string | null>();
  const children = await mapWithConcurrency(enumerated, MESH_CONCURRENCY, async (mesh) => {
    const q = mesh.meshOwner ? `?meshOwner=${encodeURIComponent(mesh.meshOwner)}` : '';
    const path = `/meshes/${encodeURIComponent(mesh.meshName)}`;
    const [describe, nodes, services] = await Promise.all([
      fetchJson(client, `${base}${path}${q}`),
      list<VirtualNodeRef>(`${path}/virtualNodes${q}`, 'virtualNodes'),
      list<VirtualServiceRef>(`${path}/virtualServices${q}`, 'virtualServices'),
    ]);
    const spec = (describe.body?.mesh as { spec?: { egressFilter?: { type?: string } } } | undefined)?.spec;
    egress.set(mesh.meshName, describe.ok ? (spec?.egressFilter?.type ?? 'DROP_ALL') : null);
    reportWalk(ctx, nodes, 'appmesh', 'ListVirtualNodes');
    reportWalk(ctx, services, 'appmesh', 'ListVirtualServices');
    return { mesh, nodes: nodes.items, services: services.items };
  });

  for (const m of meshes) {
    const egressFilter = egress.get(m.meshName);
    out.push({
      resourceTypeKey: 'app_mesh_mesh', resourceId: m.arn ?? m.meshName, region: ctx.region, resourceName: m.meshName,
      metadata: {
        meshOwner: m.meshOwner ?? null,
        resourceOwner: m.resourceOwner ?? null,
        sharedFromAnotherAccount: !!(m.meshOwner && m.resourceOwner && m.meshOwner !== m.resourceOwner),
        egressFilterCollected: egressFilter !== undefined && egressFilter !== null,
        egressFilter: egressFilter ?? null,
      },
    });
  }

  for (const { mesh, nodes, services } of children) {
    for (const n of nodes) {
      if (!n?.virtualNodeName) continue;
      out.push({ resourceTypeKey: 'app_mesh_virtual_node', resourceId: n.arn ?? `${mesh.meshName}/${n.virtualNodeName}`, region: ctx.region, resourceName: n.virtualNodeName, relationships: { meshName: mesh.meshName } });
    }
    for (const s of services) {
      if (!s?.virtualServiceName) continue;
      out.push({ resourceTypeKey: 'app_mesh_virtual_service', resourceId: s.arn ?? `${mesh.meshName}/${s.virtualServiceName}`, region: ctx.region, resourceName: s.virtualServiceName, relationships: { meshName: mesh.meshName } });
    }
  }

  return out;
}