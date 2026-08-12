import { callJsonApi } from '../awsApi';
import type { ScannedResource, ScannerContext } from './types';

const TARGET_PREFIX = 'SageMaker';

/** Every resource_type_key this scanner can produce — see ec2.ts for why discovery.ts needs this list. */
export const SAGEMAKER_RESOURCE_TYPES = ['sagemaker_notebook_instance', 'sagemaker_endpoint', 'sagemaker_training_job'] as const;

interface NotebookInstanceSummary {
  NotebookInstanceName: string; NotebookInstanceArn?: string; NotebookInstanceStatus?: string;
  InstanceType?: string; CreationTime?: number;
}
interface EndpointSummary {
  EndpointName: string; EndpointArn?: string; EndpointStatus?: string; CreationTime?: number;
}
interface TrainingJobSummary {
  TrainingJobName: string; TrainingJobArn?: string; TrainingJobStatus?: string; CreationTime?: number;
}

/** Three independent List* calls — training jobs capped at 30 (MaxResults) since an account's training history can be very large and only recent/active jobs are operationally relevant here. */
export async function scanSageMaker(ctx: ScannerContext): Promise<ScannedResource[]> {
  const endpoint = `api.sagemaker.${ctx.region}.amazonaws.com`;
  const call = async (op: string, body: Record<string, unknown> = {}) => {
    const result = await callJsonApi(ctx.creds, { service: 'sagemaker', region: ctx.region, host: endpoint, target: `${TARGET_PREFIX}.${op}`, body });
    if (!result.ok) {
      console.error(`SageMaker ${op} failed in ${ctx.region} (continuing without it): ${result.errorMessage ?? result.errorCode ?? result.status}`);
      return null;
    }
    return result.body as Record<string, unknown>;
  };

  const out: ScannedResource[] = [];

  const notebooks = await call('ListNotebookInstances');
  for (const nb of (notebooks?.NotebookInstances as NotebookInstanceSummary[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'sagemaker_notebook_instance', resourceId: nb.NotebookInstanceArn ?? nb.NotebookInstanceName, region: ctx.region,
      resourceName: nb.NotebookInstanceName, state: nb.NotebookInstanceStatus,
      metadata: { instanceType: nb.InstanceType, createdAt: nb.CreationTime },
    });
  }

  const endpoints = await call('ListEndpoints');
  for (const ep of (endpoints?.Endpoints as EndpointSummary[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'sagemaker_endpoint', resourceId: ep.EndpointArn ?? ep.EndpointName, region: ctx.region,
      resourceName: ep.EndpointName, state: ep.EndpointStatus, metadata: { createdAt: ep.CreationTime },
    });
  }

  const trainingJobs = await call('ListTrainingJobs', { MaxResults: 30, SortBy: 'CreationTime', SortOrder: 'Descending' });
  for (const tj of (trainingJobs?.TrainingJobSummaries as TrainingJobSummary[] | undefined) ?? []) {
    out.push({
      resourceTypeKey: 'sagemaker_training_job', resourceId: tj.TrainingJobArn ?? tj.TrainingJobName, region: ctx.region,
      resourceName: tj.TrainingJobName, state: tj.TrainingJobStatus, metadata: { createdAt: tj.CreationTime },
    });
  }

  return out;
}
