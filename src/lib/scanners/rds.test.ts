import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * RDS-family contract tests (rds.ts, docdb.ts, neptune.ts via rdsQuery.ts).
 *
 * callQueryApi is mocked at the awsApi boundary; importOriginal keeps every
 * other export real so the shared pagination module still loads.
 */
const callQueryApiMock = vi.fn();
vi.mock('../awsApi', async (importOriginal: () => Promise<Record<string, unknown>>) => ({
  ...(await importOriginal()),
  callQueryApi: (...args: unknown[]) => callQueryApiMock(...args),
}));

import { scanRds } from './rds';
import { scanDocDb } from './docdb';
import { scanNeptune } from './neptune';
import type { ScannedResource } from './types';

type Req = { action: string; params?: Record<string, string> };
type Failure = { normalizedCode?: string };

const creds = { accessKeyId: 'AKIA_TEST', secretAccessKey: 'secret' };
const ctx = { creds, region: 'eu-west-1' };
const ok = (body: string) => Promise.resolve({ ok: true, status: 200, body });

const wrap = (action: string, section: string, items: string, marker?: string) =>
  `<${action}Response><${action}Result>${marker ? `<Marker>${marker}</Marker>` : ''}<${section}>${items}</${section}></${action}Result></${action}Response>`;

const instance = (id: string, extra = '') =>
  `<DBInstance><DBInstanceIdentifier>${id}</DBInstanceIdentifier><Engine>postgres</Engine><DBInstanceStatus>available</DBInstanceStatus>` +
  `<StorageEncrypted>false</StorageEncrypted><PubliclyAccessible>true</PubliclyAccessible><DeletionProtection>false</DeletionProtection>` +
  `<BackupRetentionPeriod>0</BackupRetentionPeriod><IAMDatabaseAuthenticationEnabled>false</IAMDatabaseAuthenticationEnabled>` +
  `<VpcSecurityGroups><VpcSecurityGroupMembership><VpcSecurityGroupId>sg-1</VpcSecurityGroupId><Status>active</Status></VpcSecurityGroupMembership></VpcSecurityGroups>${extra}</DBInstance>`;

const cluster = (id: string, engine: string) =>
  `<DBCluster><DBClusterIdentifier>${id}</DBClusterIdentifier><Engine>${engine}</Engine><Status>available</Status>` +
  `<StorageEncrypted>true</StorageEncrypted><KmsKeyId>arn:aws:kms:eu-west-1:1:key/k</KmsKeyId><DeletionProtection>true</DeletionProtection>` +
  `<EnabledCloudwatchLogsExports><member>audit</member></EnabledCloudwatchLogsExports>` +
  `<DBClusterMembers><DBClusterMember><DBInstanceIdentifier>${id}-1</DBInstanceIdentifier></DBClusterMember></DBClusterMembers></DBCluster>`;

function serve(handlers: Record<string, (req: Req) => Promise<unknown>>) {
  callQueryApiMock.mockImplementation((_c: unknown, req: Req) => {
    const h = handlers[req.action];
    return h ? h(req) : ok(`<${req.action}Response/>`);
  });
}

const ofType = (out: ScannedResource[], t: string) => out.filter((r) => r.resourceTypeKey === t);

beforeEach(() => { callQueryApiMock.mockReset(); });

describe('RDS pagination (Marker)', () => {
  it('reads every page, following Marker', async () => {
    serve({
      DescribeDBSnapshots: (req) => req.params?.Marker === 'm2'
        ? ok(wrap('DescribeDBSnapshots', 'DBSnapshots', '<DBSnapshot><DBSnapshotIdentifier>snap-2</DBSnapshotIdentifier></DBSnapshot>'))
        : ok(wrap('DescribeDBSnapshots', 'DBSnapshots', '<DBSnapshot><DBSnapshotIdentifier>snap-1</DBSnapshotIdentifier></DBSnapshot>', 'm2')),
    });

    const snaps = ofType(await scanRds(ctx), 'rds_snapshot').map((r) => r.resourceId);
    expect(snaps).toEqual(['snap-1', 'snap-2']);
  });

  it('asks for the maximum page size', async () => {
    serve({});
    await scanRds(ctx);
    const call = callQueryApiMock.mock.calls.find((c: unknown[]) => (c[1] as Req).action === 'DescribeDBInstances');
    expect((call?.[1] as Req).params?.MaxRecords).toBe('100');
  });

  it('reports a repeated Marker as truncation instead of looping', async () => {
    const failures: Failure[] = [];
    serve({ DescribeDBInstances: () => ok(wrap('DescribeDBInstances', 'DBInstances', instance('db-1'), 'same')) });

    const out = await scanRds({ creds: { ...creds, onCallFailure: (f: Failure) => failures.push(f) }, region: 'eu-west-1' });

    expect(ofType(out, 'rds_instance').length).toBeGreaterThan(0);
    expect(failures.some((f) => f.normalizedCode === 'PAGINATION_TRUNCATED')).toBe(true);
  });

  it('keeps the other operations when one fails', async () => {
    serve({
      DescribeDBClusters: () => Promise.resolve({ ok: false, status: 403, body: '', errorCode: 'AccessDenied' }),
      DescribeDBInstances: () => ok(wrap('DescribeDBInstances', 'DBInstances', instance('db-1'))),
    });
    const out = await scanRds(ctx);
    expect(ofType(out, 'rds_instance').map((r) => r.resourceId)).toEqual(['db-1']);
  });
});

describe('RDS evidence', () => {
  it('records the instance security evidence posture needs', async () => {
    serve({ DescribeDBInstances: () => ok(wrap('DescribeDBInstances', 'DBInstances', instance('db-1'))) });

    const [db] = ofType(await scanRds(ctx), 'rds_instance');

    expect(db.metadata).toMatchObject({
      storageEncrypted: false, publiclyAccessible: true, deletionProtection: false,
      backupRetentionPeriod: 0, iamDatabaseAuthenticationEnabled: false, engine: 'postgres',
    });
    expect(db.relationships?.securityGroupIds).toEqual(['sg-1']);
  });

  it('drops null security-group ids instead of storing them', async () => {
    serve({
      DescribeDBInstances: () => ok(wrap('DescribeDBInstances', 'DBInstances',
        '<DBInstance><DBInstanceIdentifier>db-2</DBInstanceIdentifier><VpcSecurityGroups><VpcSecurityGroupMembership><Status>active</Status></VpcSecurityGroupMembership></VpcSecurityGroups></DBInstance>')),
    });
    const [db] = ofType(await scanRds(ctx), 'rds_instance');
    expect(db.relationships?.securityGroupIds).toEqual([]);
  });

  it('records a missing identifier as empty (quarantined by admission), not as a skipped row', async () => {
    serve({ DescribeDBInstances: () => ok(wrap('DescribeDBInstances', 'DBInstances', '<DBInstance><Engine>mysql</Engine></DBInstance>')) });
    const [db] = ofType(await scanRds(ctx), 'rds_instance');
    expect(db.resourceId).toBe('');
  });
});

describe('RDS / DocumentDB / Neptune cluster ownership', () => {
  const allEngines = () => ok(wrap('DescribeDBClusters', 'DBClusters',
    cluster('aurora-1', 'aurora-postgresql') + cluster('doc-1', 'docdb') + cluster('nep-1', 'neptune')));

  it('rds_cluster no longer duplicates DocumentDB and Neptune clusters', async () => {
    serve({ DescribeDBClusters: allEngines });
    expect(ofType(await scanRds(ctx), 'rds_cluster').map((r) => r.resourceId)).toEqual(['aurora-1']);
  });

  it('docdb asks for the docdb engine and never records another engine', async () => {
    serve({ DescribeDBClusters: allEngines });
    const out = await scanDocDb(ctx);
    expect(out.map((r) => r.resourceId)).toEqual(['doc-1']);
    const req = callQueryApiMock.mock.calls[0][1] as Req;
    expect(req.params?.['Filters.member.1.Values.member.1']).toBe('docdb');
  });

  it('neptune asks for the neptune engine and never records another engine', async () => {
    serve({ DescribeDBClusters: allEngines });
    const out = await scanNeptune(ctx);
    expect(out.map((r) => r.resourceId)).toEqual(['nep-1']);
  });

  it('clusters carry encryption, deletion protection, audit logs and members', async () => {
    serve({ DescribeDBClusters: allEngines });
    const [doc] = await scanDocDb(ctx);
    expect(doc.metadata).toMatchObject({
      storageEncrypted: true, deletionProtection: true, enabledCloudwatchLogsExports: ['audit'], memberCount: 1, walkComplete: true,
    });
    expect(doc.relationships?.memberInstanceIds).toEqual(['doc-1-1']);
  });

  it('docdb reads every page too', async () => {
    serve({
      DescribeDBClusters: (req) => req.params?.Marker === 'p2'
        ? ok(wrap('DescribeDBClusters', 'DBClusters', cluster('doc-2', 'docdb')))
        : ok(wrap('DescribeDBClusters', 'DBClusters', cluster('doc-1', 'docdb'), 'p2')),
    });
    expect((await scanDocDb(ctx)).map((r) => r.resourceId)).toEqual(['doc-1', 'doc-2']);
  });
});