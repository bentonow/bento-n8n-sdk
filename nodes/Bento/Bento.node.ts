import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionType, NodeOperationError } from 'n8n-workflow';
import { Buffer } from 'buffer';

export class Bento implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Bento',
		name: 'bento',
		icon: 'file:bento.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Interact with Bento email marketing platform',
		defaults: {
			name: 'Bento',
		},
		inputs: [NodeConnectionType.Main],
		outputs: [NodeConnectionType.Main],
		credentials: [
			{
				name: 'bentoApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Create Subscriber',
						value: 'createSubscriber',
						description: 'Create a new subscriber',
						action: 'Create a subscriber',
					},
					{
						name: 'Get Subscriber',
						value: 'getSubscriber',
						description: 'Get subscriber information',
						action: 'Get a subscriber',
					},
					{
						name: 'Update Subscriber',
						value: 'updateSubscriber',
						description: 'Update subscriber information',
						action: 'Update a subscriber',
					},
					{
						name: 'Track Event',
						value: 'trackEvent',
						description: 'Track a custom event',
						action: 'Track an event',
					},
				],
				default: 'createSubscriber',
			},
			{
				displayName: 'Email',
				name: 'email',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						operation: ['createSubscriber', 'getSubscriber', 'updateSubscriber'],
					},
				},
				default: '',
				placeholder: 'user@example.com',
				description: 'The email address of the subscriber',
			},
			{
				displayName: 'First Name',
				name: 'firstName',
				type: 'string',
				displayOptions: {
					show: {
						operation: ['createSubscriber', 'updateSubscriber'],
					},
				},
				default: '',
				description: 'The first name of the subscriber',
			},
			{
				displayName: 'Last Name',
				name: 'lastName',
				type: 'string',
				displayOptions: {
					show: {
						operation: ['createSubscriber', 'updateSubscriber'],
					},
				},
				default: '',
				description: 'The last name of the subscriber',
			},
			{
				displayName: 'Event Name',
				name: 'eventName',
				type: 'string',
				required: true,
				displayOptions: {
					show: {
						operation: ['trackEvent'],
					},
				},
				default: '',
				description: 'The name of the event to track',
			},
			{
				displayName: 'Event Properties',
				name: 'eventProperties',
				type: 'fixedCollection',
				typeOptions: {
					multipleValues: true,
				},
				displayOptions: {
					show: {
						operation: ['trackEvent'],
					},
				},
				default: {},
				options: [
					{
						name: 'property',
						displayName: 'Property',
						values: [
							{
								displayName: 'Key',
								name: 'key',
								type: 'string',
								default: '',
								description: 'Property key',
							},
							{
								displayName: 'Value',
								name: 'value',
								type: 'string',
								default: '',
								description: 'Property value',
							},
						],
					},
				],
				description: 'Additional properties for the event',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		for (let i = 0; i < items.length; i++) {
			try {
				const operation = this.getNodeParameter('operation', i) as string;

				// Get and validate credentials
				const credentials = await this.getCredentials('bentoApi');
				if (!credentials) {
					throw new NodeOperationError(this.getNode(), 'No credentials provided', {
						itemIndex: i,
					});
				}

				const { publishableKey, secretKey, siteUuid } = credentials;
				if (!publishableKey || !secretKey || !siteUuid) {
					throw new NodeOperationError(this.getNode(), 'Missing required credentials: publishableKey, secretKey, and siteUuid are all required', {
						itemIndex: i,
					});
				}

				// Type cast credentials to strings for safe usage
				const pubKey = publishableKey as string;
				const secKey = secretKey as string;
				const uuid = siteUuid as string;

				let responseData;

				switch (operation) {
					case 'createSubscriber': {
						const email = this.getNodeParameter('email', i) as string;
						const firstName = this.getNodeParameter('firstName', i) as string;
						const lastName = this.getNodeParameter('lastName', i) as string;

						// Example of how to use credentials for API call
						const authHeader = 'Basic ' + Buffer.from(`${pubKey}:${secKey}`).toString('base64');
						const url = `https://app.bentonow.com/api/v1/fetch/subscribers?site_uuid=${uuid}`;
						
						// This is a placeholder - actual API call would be:
						// const response = await this.helpers.httpRequest({
						//   method: 'POST',
						//   uri: url,
						//   headers: {
						//     Authorization: authHeader,
						//     'Content-Type': 'application/json',
						//   },
						//   body: { email, firstName, lastName },
						//   json: true,
						// });

						responseData = {
							operation: 'createSubscriber',
							email,
							firstName,
							lastName,
							credentials: {
								publishableKey: pubKey.substring(0, 8) + '...',
								siteUuid: uuid,
								authHeader: authHeader.substring(0, 20) + '...',
							},
							url,
							message: 'Subscriber creation placeholder - credentials validated and ready for API call',
						};
						break;
					}
					case 'getSubscriber': {
						const email = this.getNodeParameter('email', i) as string;

						responseData = {
							operation: 'getSubscriber',
							email,
							message: 'Get subscriber placeholder - implement API call',
						};
						break;
					}
					case 'updateSubscriber': {
						const email = this.getNodeParameter('email', i) as string;
						const firstName = this.getNodeParameter('firstName', i) as string;
						const lastName = this.getNodeParameter('lastName', i) as string;

						responseData = {
							operation: 'updateSubscriber',
							email,
							firstName,
							lastName,
							message: 'Update subscriber placeholder - implement API call',
						};
						break;
					}
					case 'trackEvent': {
						const eventName = this.getNodeParameter('eventName', i) as string;
						const eventProperties = this.getNodeParameter('eventProperties', i) as any;

						const properties: { [key: string]: string } = {};
						if (eventProperties.property) {
							for (const prop of eventProperties.property) {
								properties[prop.key] = prop.value;
							}
						}

						responseData = {
							operation: 'trackEvent',
							eventName,
							properties,
							message: 'Track event placeholder - implement API call',
						};
						break;
					}
					default:
						throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`, {
							itemIndex: i,
						});
				}

				returnData.push({
					json: responseData,
					pairedItem: { item: i },
				});
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: { error: error.message },
						pairedItem: { item: i },
					});
					continue;
				}
				throw error;
			}
		}

		return [returnData];
	}
}