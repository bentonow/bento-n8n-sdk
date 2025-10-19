import type { IExecuteFunctions, INodeExecutionData, INodeType, INodeTypeDescription } from 'n8n-workflow';
export declare class Bento implements INodeType {
    ai: boolean;
    aiCategory: string;
    supportsStreaming: boolean;
    inputType: string;
    outputType: string;
    description: INodeTypeDescription;
    execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]>;
}
