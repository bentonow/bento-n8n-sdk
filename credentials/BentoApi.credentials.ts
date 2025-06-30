import {
	IAuthenticateGeneric,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class BentoApi implements ICredentialType {
	name = 'bentoApi';
	displayName = 'Bento API';

	documentationUrl = 'https://docs.bentonow.com/';

	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			required: true,
			description: 'Your Bento API key',
		},
		{
			displayName: 'Site UUID',
			name: 'siteUuid',
			type: 'string',
			default: '',
			required: true,
			description: 'Your Bento site UUID',
		},
		{
			displayName: 'Base URL',
			name: 'baseUrl',
			type: 'string',
			default: 'https://app.bentonow.com',
			description: 'The base URL for Bento API (usually https://app.bentonow.com)',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Authorization: '=Bearer {{ $credentials.apiKey }}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{ $credentials.baseUrl }}',
			url: '/api/v1/site',
			headers: {
				Authorization: '=Bearer {{ $credentials.apiKey }}',
			},
		},
	};
}