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
		icon: 'fa:envelope',
		group: ['communication'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Native integration for Bento API actions',
		defaults: {
			name: 'Bento',
			color: '#FF6B35',
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
						description: 'Add a new subscriber to your Bento audience with email and profile data',
						action: 'Create a subscriber',
					},
					{
						name: 'Get Subscriber',
						value: 'getSubscriber',
						description: 'Retrieve detailed information about an existing subscriber by email',
						action: 'Get a subscriber',
					},
					{
						name: 'Update Subscriber',
						value: 'updateSubscriber',
						description: 'Modify subscriber profile information and custom attributes',
						action: 'Update a subscriber',
					},
					{
						name: 'Track Event',
						value: 'trackEvent',
						description: 'Record custom events and behaviors for subscriber segmentation and automation',
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
				description: 'The email address of the subscriber - must be a valid email format',
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
				placeholder: 'John',
				description: 'The first name of the subscriber for personalization',
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
				placeholder: 'Doe',
				description: 'The last name of the subscriber for personalization',
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
				placeholder: 'purchase_completed',
				description: 'The name of the custom event to track (e.g., purchase_completed, page_viewed)',
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
				description: 'Additional properties and data to attach to the event for segmentation and personalization',
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