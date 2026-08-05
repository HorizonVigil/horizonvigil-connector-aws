import { callQueryApi, listParams, type AwsCreds, type AwsCallResult } from './awsApi';
import { field, extractSection, extractListItems } from './xmlList';

const VERSION = '2016-11-15';

export type RemediationActionType = 'stop_instance' | 'start_instance' | 'release_eip' | 'delete_volume' | 'delete_snapshot' | 'deregister_ami' | 'resize_instance';

export interface EligibilityCheck {
  eligible: boolean;
  reason?: string;
  state?: string;
}

/**
 * Re-checks a resource's *live* AWS state right before dry-run/execute,
 * rather than trusting cloud_resources (which is only as fresh as the last
 * discovery scan) — an instance approved for stop_instance an hour ago may
 * already be stopped, terminated, or gone by the time someone actually
 * executes it, and this is the guard that catches that race.
 */
export async function describeCurrentState(creds: AwsCreds, region: string, actionType: RemediationActionType, targetResourceId: string): Promise<EligibilityCheck> {
  const endpoint = `ec2.${region}.amazonaws.com`;
  const describe = (action: string, params: Record<string, string>) =>
    callQueryApi(creds, { service: 'ec2', region, host: endpoint, action, version: VERSION, params });

  if (actionType === 'stop_instance' || actionType === 'start_instance') {
    const result = await describe('DescribeInstances', listParams('InstanceId', [targetResourceId]));
    if (!result.ok) return { eligible: false, reason: result.errorMessage ?? result.errorCode ?? 'DescribeInstances failed' };
    const instance = extractListItems(extractSection(result.body as string, 'reservationSet'))
      .flatMap((r) => extractListItems(extractSection(r, 'instancesSet')))[0];
    if (!instance) return { eligible: false, reason: 'Instance not found.' };
    const stateSection = extractSection(instance, 'instanceState');
    const state = stateSection ? field(stateSection, 'name') : null;
    const wantState = actionType === 'stop_instance' ? 'running' : 'stopped';
    return state === wantState ? { eligible: true, state } : { eligible: false, reason: `Instance is currently '${state}', not '${wantState}'.`, state: state ?? undefined };
  }

  if (actionType === 'release_eip') {
    const result = await describe('DescribeAddresses', listParams('AllocationId', [targetResourceId]));
    if (!result.ok) return { eligible: false, reason: result.errorMessage ?? result.errorCode ?? 'DescribeAddresses failed' };
    const addr = extractListItems(extractSection(result.body as string, 'addressesSet'))[0];
    if (!addr) return { eligible: false, reason: 'Elastic IP not found.' };
    const instanceId = field(addr, 'instanceId');
    const eniId = field(addr, 'networkInterfaceId');
    return !instanceId && !eniId ? { eligible: true } : { eligible: false, reason: 'Elastic IP is currently associated with an instance/network interface.' };
  }

  if (actionType === 'delete_volume') {
    const result = await describe('DescribeVolumes', listParams('VolumeId', [targetResourceId]));
    if (!result.ok) return { eligible: false, reason: result.errorMessage ?? result.errorCode ?? 'DescribeVolumes failed' };
    const volume = extractListItems(extractSection(result.body as string, 'volumeSet'))[0];
    if (!volume) return { eligible: false, reason: 'Volume not found.' };
    const status = field(volume, 'status');
    const attached = extractListItems(extractSection(volume, 'attachmentSet'));
    return attached.length === 0 && status !== 'in-use'
      ? { eligible: true, state: status ?? undefined }
      : { eligible: false, reason: 'Volume is currently attached to an instance.', state: status ?? undefined };
  }

  if (actionType === 'delete_snapshot') {
    const result = await describe('DescribeSnapshots', listParams('SnapshotId', [targetResourceId]));
    if (!result.ok) return { eligible: false, reason: result.errorMessage ?? result.errorCode ?? 'DescribeSnapshots failed' };
    const snapshot = extractListItems(extractSection(result.body as string, 'snapshotSet'))[0];
    if (!snapshot) return { eligible: false, reason: 'Snapshot not found.' };
    const status = field(snapshot, 'status');
    // A snapshot backing a registered AMI can't actually be deleted — AWS
    // itself rejects it server-side (InvalidSnapshot.InUse), which the
    // DryRun step below will surface honestly. Not pre-checked here (would
    // need a second DescribeImages call filtered on block-device-mapping)
    // since AWS's own validation is already the authoritative source.
    return status === 'completed'
      ? { eligible: true, state: status }
      : { eligible: false, reason: `Snapshot is currently '${status}', not 'completed'.`, state: status ?? undefined };
  }

  if (actionType === 'resize_instance') {
    // Eligible from either state — 'running' means execute will stop it
    // first (see routes/remediation.ts's two-phase execute/finish-resize),
    // 'stopped' means it can resize immediately. Anything else (pending,
    // stopping, shutting-down, terminated) genuinely can't be resized right
    // now, the same honest reasoning as every other state check here.
    const result = await describe('DescribeInstances', listParams('InstanceId', [targetResourceId]));
    if (!result.ok) return { eligible: false, reason: result.errorMessage ?? result.errorCode ?? 'DescribeInstances failed' };
    const instance = extractListItems(extractSection(result.body as string, 'reservationSet'))
      .flatMap((r) => extractListItems(extractSection(r, 'instancesSet')))[0];
    if (!instance) return { eligible: false, reason: 'Instance not found.' };
    const stateSection = extractSection(instance, 'instanceState');
    const state = stateSection ? field(stateSection, 'name') : null;
    return state === 'running' || state === 'stopped'
      ? { eligible: true, state }
      : { eligible: false, reason: `Instance is currently '${state}' — must be 'running' or 'stopped' to resize.`, state: state ?? undefined };
  }

  // deregister_ami
  const result = await describe('DescribeImages', listParams('ImageId', [targetResourceId]));
  if (!result.ok) return { eligible: false, reason: result.errorMessage ?? result.errorCode ?? 'DescribeImages failed' };
  const image = extractListItems(extractSection(result.body as string, 'imagesSet'))[0];
  if (!image) return { eligible: false, reason: 'AMI not found — it may already be deregistered.' };
  const imageState = field(image, 'imageState');
  return imageState === 'available'
    ? { eligible: true, state: imageState }
    : { eligible: false, reason: `AMI is currently '${imageState}', not 'available'.`, state: imageState ?? undefined };
}

/**
 * Every action this module can take is a real, mutating EC2 API call using
 * the connection's own stored credentials — no platform-level AWS access is
 * involved. Whether a call actually succeeds is entirely governed by the
 * IAM permissions attached to *that customer's* connected access
 * key/role — an AccessDenied/UnauthorizedOperation response here is
 * correct, expected behavior for a read-only-scoped connection, not a bug.
 *
 * `dryRun: true` uses AWS's own DryRun parameter (every mutating EC2 call
 * supports it) rather than a client-side simulation: AWS validates
 * permissions and resource state server-side and replies with the
 * pseudo-error `DryRunOperation` (would succeed) or `UnauthorizedOperation`
 * (would fail on permissions) without performing the action — a real
 * safety check, not a fake one.
 */
async function callEc2Action(creds: AwsCreds, region: string, action: string, params: Record<string, string>, dryRun: boolean): Promise<AwsCallResult> {
  return callQueryApi(creds, {
    service: 'ec2', region, host: `ec2.${region}.amazonaws.com`, action, version: VERSION,
    params: { ...params, DryRun: String(dryRun) },
  });
}

export function stopInstance(creds: AwsCreds, region: string, instanceId: string, dryRun: boolean) {
  return callEc2Action(creds, region, 'StopInstances', listParams('InstanceId', [instanceId]), dryRun);
}
export function startInstance(creds: AwsCreds, region: string, instanceId: string, dryRun: boolean) {
  return callEc2Action(creds, region, 'StartInstances', listParams('InstanceId', [instanceId]), dryRun);
}
export function releaseEip(creds: AwsCreds, region: string, allocationId: string, dryRun: boolean) {
  return callEc2Action(creds, region, 'ReleaseAddress', { AllocationId: allocationId }, dryRun);
}
export function deleteVolume(creds: AwsCreds, region: string, volumeId: string, dryRun: boolean) {
  return callEc2Action(creds, region, 'DeleteVolume', { VolumeId: volumeId }, dryRun);
}
export function deleteSnapshot(creds: AwsCreds, region: string, snapshotId: string, dryRun: boolean) {
  return callEc2Action(creds, region, 'DeleteSnapshot', { SnapshotId: snapshotId }, dryRun);
}
export function deregisterAmi(creds: AwsCreds, region: string, imageId: string, dryRun: boolean) {
  return callEc2Action(creds, region, 'DeregisterImage', { ImageId: imageId }, dryRun);
}

/**
 * ModifyInstanceAttribute for InstanceType — AWS rejects this outright
 * (IncorrectInstanceState) unless the instance is already stopped, which is
 * exactly why resize_instance is the one remediation action that can't be a
 * single runAction() call: routes/remediation.ts's execute/finish-resize
 * pair calls stopInstance first (if needed), waits for the caller to
 * confirm the instance is actually stopped, then calls this.
 */
export function modifyInstanceType(creds: AwsCreds, region: string, instanceId: string, targetInstanceType: string, dryRun: boolean) {
  return callEc2Action(creds, region, 'ModifyInstanceAttribute', { InstanceId: instanceId, 'InstanceType.Value': targetInstanceType }, dryRun);
}

/**
 * Mandatory safety net for delete_volume, never itself run as a dry-run —
 * a real snapshot taken immediately before the real delete, so "delete an
 * unattached volume" is recoverable even though the volume itself isn't.
 * Returns the new snapshot's id so it can be recorded on the request.
 */
export async function createSafetySnapshot(creds: AwsCreds, region: string, volumeId: string, description: string): Promise<{ snapshotId: string } | { error: string }> {
  const result = await callEc2Action(creds, region, 'CreateSnapshot', { VolumeId: volumeId, Description: description }, false);
  if (!result.ok) return { error: result.errorMessage ?? result.errorCode ?? 'CreateSnapshot failed' };
  const snapshotId = field(result.body as string, 'snapshotId');
  if (!snapshotId) return { error: 'CreateSnapshot succeeded but no snapshotId was returned' };
  return { snapshotId };
}

/**
 * `targetInstanceType` only means anything for 'resize_instance' — every
 * other action type ignores it. Used for resize's dry-run (checks
 * ModifyInstanceAttribute permission specifically, the actual differentiating
 * call) and for the finish-resize step of its real execute; the *first*
 * phase of a real resize execute (stopping a running instance) goes through
 * stopInstance directly in routes/remediation.ts, not through here — see
 * modifyInstanceType's doc comment for why resize can't be one runAction call.
 */
export function runAction(creds: AwsCreds, region: string, actionType: RemediationActionType, targetResourceId: string, dryRun: boolean, targetInstanceType?: string): Promise<AwsCallResult> {
  switch (actionType) {
    case 'stop_instance': return stopInstance(creds, region, targetResourceId, dryRun);
    case 'start_instance': return startInstance(creds, region, targetResourceId, dryRun);
    case 'release_eip': return releaseEip(creds, region, targetResourceId, dryRun);
    case 'delete_volume': return deleteVolume(creds, region, targetResourceId, dryRun);
    case 'delete_snapshot': return deleteSnapshot(creds, region, targetResourceId, dryRun);
    case 'deregister_ami': return deregisterAmi(creds, region, targetResourceId, dryRun);
    case 'resize_instance':
      if (!targetInstanceType) return Promise.resolve({ ok: false, status: 0, body: null, errorMessage: 'No target instance type provided for resize' });
      return modifyInstanceType(creds, region, targetResourceId, targetInstanceType, dryRun);
  }
}

export interface DryRunOutcome {
  [key: string]: unknown;
  wouldSucceed: boolean;
  reason?: string;
}

export function interpretDryRun(result: AwsCallResult): DryRunOutcome {
  if (result.errorCode === 'DryRunOperation') return { wouldSucceed: true };
  if (result.errorCode === 'UnauthorizedOperation') return { wouldSucceed: false, reason: "The connection's AWS credentials do not have permission to perform this action." };
  if (result.ok) return { wouldSucceed: true };
  return { wouldSucceed: false, reason: result.errorMessage ?? result.errorCode ?? 'Unknown error' };
}
