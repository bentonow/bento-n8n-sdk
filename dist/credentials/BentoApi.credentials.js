"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BentoApi = void 0;
class BentoApi {
    constructor() {
        this.name = 'bentoApi';
        this.displayName = 'Bento API';
        this.documentationUrl = 'https://docs.bentonow.com/';
        this.properties = [
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
        this.authenticate = {
            type: 'generic',
            properties: {
                auth: {
                    username: '={{ $credentials.publishableKey }}',
                    password: '={{ $credentials.secretKey }}',
                },
            },
        };
        this.test = {
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
}
exports.BentoApi = BentoApi;
//# sourceMappingURL=BentoApi.credentials.js.map