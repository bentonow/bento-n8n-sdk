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
			displayName: 'Publishable Key',
			name: 'publishableKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description: 'Your Bento publishable key - used for client-side operations',
		},
		{
			displayName: 'Secret Key',
			name: 'secretKey',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			required: true,
			description: 'Your Bento secret key - used for server-side operations (keep secure)',
		},
		{
			displayName: 'Site UUID',
			name: 'siteUuid',
			type: 'string',
			default: '',
			required: true,
			description: 'Your Bento site UUID - identifies your specific Bento site',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			auth: {
				username: '={{ $credentials.publishableKey }}',
				password: '={{ $credentials.secretKey }}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: 'https://app.bentonow.com',
			url: '=/api/v1/fetch/tags?site_uuid={{ $credentials.siteUuid }}',
			auth: {
				username: '={{ $credentials.publishableKey }}',
				password: '={{ $credentials.secretKey }}',
			},
		},
	};
}