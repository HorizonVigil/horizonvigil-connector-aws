import { createAwsClient, safeFetch } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const APPMESH_RESOURCE_TYPES = ['app_mesh_mesh', 'app_mesh_virtual_node', 'app_mesh_virtual_service'] as const;

interface MeshRef { meshName: string; arn?: string }
interface ListMeshesResponse { meshes?: MeshRef[] }
interface VirtualNodeRef { virtualNodeName: string; arn?: string; meshName?: string }
interface ListVirtualNodesResponse { virtualNodes?: VirtualNodeRef[] }
interface VirtualServiceRef { virtualServiceName: string; arn?: string; meshName?: string }
interface ListVirtualServicesResponse { virtualServices?: VirtualServiceRef[] }

/** AWS App Mesh — REST-JSON, versioned path prefix /v20190125/. */
export async function scanAppMesh(ctx: ScannerContext): Promise<ScannedResource[]> {
  const client = createAwsClient(ctx.creds, 'appmesh', ctx.region);
  const base = `https://appmesh.${ctx.region}.amazonaws.com/v20190125`;

  const getJson = async (path: string): Promise<Record<string, unknown> | null> => {
    const res = await safeFetch(client, `${base}${path}`, { method: 'GET' });
    const text = await res.text();
    if (!res.ok) {
      console.error(`App Mesh GET ${path} failed in ${ctx.region} (continuing without it): HTTP ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return text ? (JSON.parse(text) as Record<string, unknown>) : {};
  };

  const out: ScannedResource[] = [];

  const meshesResult = (await getJson('/meshes')) as ListMeshesResponse | null;
  if (!meshesResult) return out;
  const meshes = meshesResult.meshes ?? [];
  for (const m of meshes) {
    out.push({ resourceTypeKey: 'app_mesh_mesh', resourceId: m.arn ?? m.meshName, region: ctx.region, resourceName: m.meshName });
  }

  for (const mesh of meshes.slice(0, 10)) {
    const nodesResult = (await getJson(`/meshes/${encodeURIComponent(mesh.meshName)}/virtualNodes`)) as ListVirtualNodesResponse | null;
    for (const n of nodesResult?.virtualNodes ?? []) {
      out.push({ resourceTypeKey: 'app_mesh_virtual_node', resourceId: n.arn ?? `${mesh.meshName}/${n.virtualNodeName}`, region: ctx.region, resourceName: n.virtualNodeName, relationships: { meshName: mesh.meshName } });
    }
    const servicesResult = (await getJson(`/meshes/${encodeURIComponent(mesh.meshName)}/virtualServices`)) as ListVirtualServicesResponse | null;
    for (const s of servicesResult?.virtualServices ?? []) {
      out.push({ resourceTypeKey: 'app_mesh_virtual_service', resourceId: s.arn ?? `${mesh.meshName}/${s.virtualServiceName}`, region: ctx.region, resourceName: s.virtualServiceName, relationships: { meshName: mesh.meshName } });
    }
  }

  return out;
}
