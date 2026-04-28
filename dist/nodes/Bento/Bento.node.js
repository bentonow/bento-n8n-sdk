"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Bento = void 0;
const n8n_workflow_1 = require("n8n-workflow");
const buffer_1 = require("buffer");
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const INPUT_LIMITS = {
    EMAIL: 254,
    RESOURCE_ID: 100,
    NAME: 50,
    TAG_NAME: 100,
    SUBJECT: 200,
    CUSTOM_FIELD_KEY: 50,
    CUSTOM_FIELD_VALUE: 500,
    EVENT_NAME: 100,
    EVENT_PROPERTY_KEY: 50,
    EVENT_PROPERTY_VALUE: 500,
    HTML_CONTENT: 50000,
    INBOX_SNIPPET: 500,
    TEXT_CONTENT: 50000,
    USER_ID: 254,
    IP_ADDRESS: 45,
    VALIDATE_NAME: 100,
    USER_AGENT: 512,
    SEGMENT_ID: 100,
};
const DANGEROUS_HTML_PATTERNS = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<iframe\b[^>]*>/gi,
    /<object\b[^>]*>/gi,
    /<embed\b[^>]*>/gi,
    /<form\b[^>]*>/gi,
    /<input\b[^>]*>/gi,
    /<meta\b[^>]*>/gi,
    /<link\b[^>]*>/gi,
    /data:(?!image\/)/gi,
    /<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi,
];
const DANGEROUS_TEMPLATE_HTML_PATTERNS = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<iframe\b[^>]*>/gi,
    /<object\b[^>]*>/gi,
    /<embed\b[^>]*>/gi,
    /<form\b[^>]*>/gi,
    /<input\b[^>]*>/gi,
    /<meta\b[^>]*>/gi,
    /<link\b[^>]*>/gi,
    /data:(?!image\/)/gi,
];
const SECURE_ERROR_MESSAGES = {
    AUTHENTICATION_FAILED: 'Authentication failed. Please check your Bento API credentials.',
    INVALID_REQUEST: 'Request validation failed. Please check your input parameters.',
    API_ERROR: 'Bento API request failed. Please try again or contact support.',
    NETWORK_ERROR: 'Network error occurred. Please check your connection and try again.',
    VALIDATION_ERROR: 'Input validation failed. Please check your data format.',
    RATE_LIMITED: 'Rate limit exceeded. Please wait before making more requests.',
    SERVER_ERROR: 'Server error occurred. Please try again later.',
    UNKNOWN_ERROR: 'An unexpected error occurred. Please contact support if the issue persists.',
};
const REQUEST_LIMITS = {
    MAX_PAYLOAD_SIZE: 1024 * 1024,
    DEFAULT_TIMEOUT: 30000,
    MAX_RETRIES: 3,
    RETRY_DELAY_BASE: 1000,
    RATE_LIMIT_DELAY: 60000,
    MAX_CONCURRENT_REQUESTS: 5,
};
const RETRYABLE_STATUS_CODES = [429, 500, 502, 503, 504];
const RETRYABLE_ERROR_CODES = ['ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'ECONNREFUSED'];
function isValidEmail(email) {
    if (typeof email !== 'string' || email.trim() === '') {
        return false;
    }
    const trimmedEmail = email.trim();
    if (trimmedEmail.length > 254) {
        return false;
    }
    if (!EMAIL_REGEX.test(trimmedEmail)) {
        return false;
    }
    if (trimmedEmail.includes('..')) {
        return false;
    }
    if (trimmedEmail.startsWith('.') || trimmedEmail.endsWith('.')) {
        return false;
    }
    const [localPart, domainPart] = trimmedEmail.split('@');
    if (localPart.length > 64) {
        return false;
    }
    if (domainPart.length > 253) {
        return false;
    }
    const domainParts = domainPart.split('.');
    if (domainParts.length < 2) {
        return false;
    }
    for (const part of domainParts) {
        if (part.length === 0 || part.length > 63) {
            return false;
        }
        if (part.startsWith('-') || part.endsWith('-')) {
            return false;
        }
    }
    return true;
}
function sanitizeEmail(email) {
    if (typeof email !== 'string') {
        return '';
    }
    return email.trim().toLowerCase();
}
function validateHtmlContent(html) {
    if (typeof html !== 'string') {
        return false;
    }
    for (const pattern of DANGEROUS_HTML_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        if (regex.test(html)) {
            return false;
        }
    }
    return true;
}
function sanitizeHtmlContent(html) {
    if (typeof html !== 'string') {
        return '';
    }
    let sanitized = html.trim();
    for (const pattern of DANGEROUS_HTML_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        sanitized = sanitized.replace(regex, '');
    }
    sanitized = sanitized.replace(/javascript\s*:/gi, '');
    sanitized = sanitized.replace(/vbscript\s*:/gi, '');
    sanitized = sanitized.replace(/data\s*:/gi, '');
    return sanitized;
}
function validateTemplateHtmlContent(html) {
    if (typeof html !== 'string') {
        return false;
    }
    for (const pattern of DANGEROUS_TEMPLATE_HTML_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        if (regex.test(html)) {
            return false;
        }
    }
    return true;
}
function sanitizeTemplateHtmlContent(html) {
    if (typeof html !== 'string') {
        return '';
    }
    let sanitized = html.trim();
    for (const pattern of DANGEROUS_TEMPLATE_HTML_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        sanitized = sanitized.replace(regex, '');
    }
    sanitized = sanitized.replace(/javascript\s*:/gi, '');
    sanitized = sanitized.replace(/vbscript\s*:/gi, '');
    return sanitized;
}
function validateHtmlStructure(html) {
    const issues = [];
    if (typeof html !== 'string') {
        issues.push('HTML content must be a string');
        return { isValid: false, issues };
    }
    if (/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi.test(html)) {
        issues.push('Script tags are not allowed');
    }
    if (/javascript:/gi.test(html)) {
        issues.push('JavaScript URLs are not allowed');
    }
    if (/on\w+\s*=/gi.test(html)) {
        issues.push('Event handlers (onclick, onload, etc.) are not allowed');
    }
    if (/<iframe\b[^>]*>/gi.test(html)) {
        issues.push('Iframe tags are not allowed');
    }
    if (/<form\b[^>]*>/gi.test(html)) {
        issues.push('Form tags are not allowed in email content');
    }
    if (/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi.test(html)) {
        issues.push('Style tags are not recommended (use inline styles instead)');
    }
    const openTags = html.match(/<[^\/][^>]*>/g) || [];
    const closeTags = html.match(/<\/[^>]*>/g) || [];
    if (openTags.length !== closeTags.length) {
        issues.push('HTML may contain unclosed tags');
    }
    return {
        isValid: issues.length === 0,
        issues
    };
}
function validateInputLength(input, maxLength, fieldName, itemIndex) {
    if (typeof input === 'string' && input.length > maxLength) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), `${fieldName} exceeds maximum length of ${maxLength} characters (current: ${input.length})`, { itemIndex });
    }
}
function validatePositiveIntegerInput(input, fieldName, itemIndex) {
    if (!Number.isFinite(input) || input <= 0 || !Number.isInteger(input)) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), `${fieldName} must be a positive whole number`, { itemIndex });
    }
    return input;
}
function createSecureErrorMessage(error, operation) {
    if (error.statusCode) {
        switch (error.statusCode) {
            case 400:
                return `${SECURE_ERROR_MESSAGES.INVALID_REQUEST} (Operation: ${operation})`;
            case 401:
                return SECURE_ERROR_MESSAGES.AUTHENTICATION_FAILED;
            case 403:
                return SECURE_ERROR_MESSAGES.AUTHENTICATION_FAILED;
            case 404:
                return `${SECURE_ERROR_MESSAGES.API_ERROR} Resource not found.`;
            case 429:
                return SECURE_ERROR_MESSAGES.RATE_LIMITED;
            case 500:
            case 502:
            case 503:
            case 504:
                return SECURE_ERROR_MESSAGES.SERVER_ERROR;
            default:
                return SECURE_ERROR_MESSAGES.API_ERROR;
        }
    }
    if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
        return SECURE_ERROR_MESSAGES.NETWORK_ERROR;
    }
    if (error.message && error.message.includes('validation')) {
        return SECURE_ERROR_MESSAGES.VALIDATION_ERROR;
    }
    return SECURE_ERROR_MESSAGES.UNKNOWN_ERROR;
}
function logSecureError(error, operation, context) {
    var _a;
    this.logger.error('Bento Node Error', {
        operation,
        itemIndex: context.itemIndex,
        endpoint: context.endpoint,
        statusCode: error.statusCode,
        errorCode: error.code,
        hasMessage: !!error.message,
        messageLength: ((_a = error.message) === null || _a === void 0 ? void 0 : _a.length) || 0,
        timestamp: new Date().toISOString(),
    });
}
function validatePayloadSize(body) {
    if (!body)
        return true;
    const payloadSize = JSON.stringify(body).length;
    return payloadSize <= REQUEST_LIMITS.MAX_PAYLOAD_SIZE;
}
function calculateBackoffDelay(attempt, baseDelay = REQUEST_LIMITS.RETRY_DELAY_BASE) {
    const exponentialDelay = baseDelay * Math.pow(2, attempt);
    const jitter = Math.random() * 0.1 * exponentialDelay;
    return Math.min(exponentialDelay + jitter, 30000);
}
function shouldRetryRequest(error, attempt) {
    if (attempt >= REQUEST_LIMITS.MAX_RETRIES) {
        return false;
    }
    if (error.statusCode && RETRYABLE_STATUS_CODES.includes(error.statusCode)) {
        return true;
    }
    if (error.code && RETRYABLE_ERROR_CODES.includes(error.code)) {
        return true;
    }
    return false;
}
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
const activeRequests = new Map();
const requestQueue = new Map();
async function acquireRequestSlot(nodeId) {
    const currentRequests = activeRequests.get(nodeId) || 0;
    if (currentRequests >= REQUEST_LIMITS.MAX_CONCURRENT_REQUESTS) {
        const queue = requestQueue.get(nodeId) || [];
        return new Promise((resolve) => {
            queue.push(resolve);
            requestQueue.set(nodeId, queue);
        });
    }
    activeRequests.set(nodeId, currentRequests + 1);
}
function releaseRequestSlot(nodeId) {
    const currentRequests = activeRequests.get(nodeId) || 0;
    const newCount = Math.max(0, currentRequests - 1);
    activeRequests.set(nodeId, newCount);
    const queue = requestQueue.get(nodeId) || [];
    if (queue.length > 0 && newCount < REQUEST_LIMITS.MAX_CONCURRENT_REQUESTS) {
        const nextResolve = queue.shift();
        if (nextResolve) {
            requestQueue.set(nodeId, queue);
            activeRequests.set(nodeId, newCount + 1);
            nextResolve();
        }
    }
}
class Bento {
    constructor() {
        this.ai = true;
        this.aiCategory = 'automation';
        this.supportsStreaming = false;
        this.inputType = 'json';
        this.outputType = 'json';
        this.description = {
            displayName: 'Bento',
            name: 'bento',
            icon: 'file:bento.svg',
            group: ['communication'],
            version: 1,
            subtitle: '={{$parameter["operation"]}}',
            description: 'Native integration for Bento API actions',
            defaults: {
                name: 'Bento',
            },
            inputs: ["main"],
            outputs: ["main"],
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
                            name: 'Blacklist Check',
                            value: 'blacklistCheck',
                            description: 'Check an email against Bento\'s blacklist service',
                            action: 'Check email against blacklist',
                        },
                        {
                            name: 'Content Moderation',
                            value: 'contentModeration',
                            description: 'Send content to Bento\'s moderation service',
                            action: 'Moderate content',
                        },
                        {
                            name: 'Create Field',
                            value: 'createField',
                            description: 'Create a Bento custom field definition',
                            action: 'Create a field',
                        },
                        {
                            name: 'Create Sequence Email',
                            value: 'createSequenceEmail',
                            description: 'Add a new email template to an existing Bento sequence',
                            action: 'Create a sequence email',
                        },
                        {
                            name: 'Create Subscriber',
                            value: 'createSubscriber',
                            description: 'Add a new subscriber to your Bento audience with email and profile data',
                            action: 'Create a subscriber',
                        },
                        {
                            name: 'Create Tag',
                            value: 'createTag',
                            description: 'Create a Bento tag for audience segmentation',
                            action: 'Create a tag',
                        },
                        {
                            name: 'Gender Guess',
                            value: 'genderGuess',
                            description: 'Predict subscriber gender using Bento\'s experimental classifier',
                            action: 'Guess gender',
                        },
                        {
                            name: 'Geolocation Lookup',
                            value: 'geolocationLookup',
                            description: 'Look up location details for an IP address',
                            action: 'Look up geolocation',
                        },
                        {
                            name: 'Get Email Template',
                            value: 'getEmailTemplate',
                            description: 'Fetch a Bento email template by ID',
                            action: 'Get an email template',
                        },
                        {
                            name: 'Get Subscriber',
                            value: 'getSubscriber',
                            description: 'Retrieve detailed information about an existing subscriber by email',
                            action: 'Get a subscriber',
                        },
                        {
                            name: 'List Broadcasts',
                            value: 'listBroadcasts',
                            description: 'List Bento broadcasts with optional filters',
                            action: 'List broadcasts',
                        },
                        {
                            name: 'List Fields',
                            value: 'listFields',
                            description: 'List Bento custom fields for the current site',
                            action: 'List fields',
                        },
                        {
                            name: 'List Sequences',
                            value: 'listSequences',
                            description: 'List Bento sequences, including their embedded email templates',
                            action: 'List sequences',
                        },
                        {
                            name: 'List Tags',
                            value: 'listTags',
                            description: 'List Bento tags available for the current site',
                            action: 'List tags',
                        },
                        {
                            name: 'List Workflows',
                            value: 'listWorkflows',
                            description: 'List Bento workflows and their embedded email templates',
                            action: 'List workflows',
                        },
                        {
                            name: 'Report Metrics',
                            value: 'reportStats',
                            description: 'Pull Bento analytics reports for broadcasts, automations, or revenue',
                            action: 'Fetch report metrics',
                        },
                        {
                            name: 'Segment Metrics',
                            value: 'segmentStats',
                            description: 'Fetch segment-level analytics for a selected date range',
                            action: 'Fetch segment metrics',
                        },
                        {
                            name: 'Send Broadcast',
                            value: 'sendBroadcast',
                            description: 'Send a broadcast immediately or at a scheduled time',
                            action: 'Send a broadcast',
                        },
                        {
                            name: 'Send Transactional Email',
                            value: 'sendTransactionalEmail',
                            description: 'Send personalized transactional emails using Bento templates',
                            action: 'Send a transactional email',
                        },
                        {
                            name: 'Site Metrics',
                            value: 'siteStats',
                            description: 'Fetch site-wide analytics for a selected date range',
                            action: 'Fetch site metrics',
                        },
                        {
                            name: 'Subscriber Command',
                            value: 'subscriberCommand',
                            description: 'Execute commands on subscribers (add/remove tags, fields, subscribe/unsubscribe, etc.)',
                            action: 'Execute a subscriber command',
                        },
                        {
                            name: 'Track Event',
                            value: 'trackEvent',
                            description: 'Record custom events and behaviors for subscriber segmentation and automation',
                            action: 'Track an event',
                        },
                        {
                            name: 'Update Email Template',
                            value: 'updateEmailTemplate',
                            description: 'Update a Bento email template\'s subject and/or HTML',
                            action: 'Update an email template',
                        },
                        {
                            name: 'Update Subscriber',
                            value: 'updateSubscriber',
                            description: 'Modify subscriber profile information and custom attributes',
                            action: 'Update a subscriber',
                        },
                        {
                            name: 'Validate Email',
                            value: 'validateEmail',
                            description: 'Validate email address for spam/throwaway detection',
                            action: 'Validate an email address',
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
                    displayName: 'Custom Fields',
                    name: 'customFields',
                    type: 'fixedCollection',
                    typeOptions: {
                        multipleValues: true,
                    },
                    displayOptions: {
                        show: {
                            operation: ['createSubscriber', 'updateSubscriber'],
                        },
                    },
                    default: {},
                    options: [
                        {
                            name: 'field',
                            displayName: 'Field',
                            values: [
                                {
                                    displayName: 'Key',
                                    name: 'key',
                                    type: 'string',
                                    default: '',
                                    placeholder: 'company',
                                    description: 'Custom field name',
                                },
                                {
                                    displayName: 'Value',
                                    name: 'value',
                                    type: 'string',
                                    default: '',
                                    placeholder: 'Acme Corp',
                                    description: 'Custom field value',
                                },
                            ],
                        },
                    ],
                    description: 'Additional custom fields to store with the subscriber',
                },
                {
                    displayName: 'Page',
                    name: 'listSequencesPage',
                    type: 'number',
                    typeOptions: {
                        minValue: 1,
                    },
                    displayOptions: {
                        show: {
                            operation: ['listSequences'],
                        },
                    },
                    default: 1,
                    description: 'Page number of sequences to retrieve',
                },
                {
                    displayName: 'Sequence ID',
                    name: 'createSequenceEmailSequenceId',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['createSequenceEmail'],
                        },
                    },
                    default: '',
                    placeholder: 'seq_12345',
                    description: 'Identifier of the Bento sequence that should receive the new email template',
                },
                {
                    displayName: 'Subject',
                    name: 'createSequenceEmailSubject',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['createSequenceEmail'],
                        },
                    },
                    default: '',
                    placeholder: 'Welcome to the sequence',
                    description: 'Subject line for the sequence email',
                },
                {
                    displayName: 'HTML',
                    name: 'createSequenceEmailHtml',
                    type: 'string',
                    typeOptions: {
                        rows: 8,
                    },
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['createSequenceEmail'],
                        },
                    },
                    default: '',
                    placeholder: '<p>Thanks for joining {{ first_name }}</p>',
                    description: 'HTML body for the sequence email template',
                },
                {
                    displayName: 'Inbox Snippet',
                    name: 'createSequenceEmailInboxSnippet',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['createSequenceEmail'],
                        },
                    },
                    default: '',
                    placeholder: 'Preview text shown in inboxes',
                    description: 'Optional preheader text shown in supported inboxes',
                },
                {
                    displayName: 'Delay Interval',
                    name: 'createSequenceEmailDelayInterval',
                    type: 'options',
                    displayOptions: {
                        show: {
                            operation: ['createSequenceEmail'],
                        },
                    },
                    options: [
                        {
                            name: 'Days',
                            value: 'days',
                        },
                        {
                            name: 'Hours',
                            value: 'hours',
                        },
                        {
                            name: 'Minutes',
                            value: 'minutes',
                        },
                        {
                            name: 'Months',
                            value: 'months',
                        },
                        {
                            name: 'None',
                            value: '',
                        },
                    ],
                    default: '',
                    description: 'Optional delay unit before Bento sends this sequence email',
                },
                {
                    displayName: 'Delay Interval Count',
                    name: 'createSequenceEmailDelayIntervalCount',
                    type: 'number',
                    typeOptions: {
                        minValue: 1,
                    },
                    displayOptions: {
                        show: {
                            operation: ['createSequenceEmail'],
                            createSequenceEmailDelayInterval: ['minutes', 'hours', 'days', 'months'],
                        },
                    },
                    default: 1,
                    description: 'Delay count to pair with the selected delay interval',
                },
                {
                    displayName: 'Editor Choice',
                    name: 'createSequenceEmailEditorChoice',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['createSequenceEmail'],
                        },
                    },
                    default: '',
                    placeholder: 'classic',
                    description: 'Optional editor mode to use when Bento stores the template',
                },
                {
                    displayName: 'To',
                    name: 'createSequenceEmailTo',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['createSequenceEmail'],
                        },
                    },
                    default: '',
                    placeholder: 'subscriber@example.com',
                    description: 'Optional To header override used by Bento for the email template',
                },
                {
                    displayName: 'CC',
                    name: 'createSequenceEmailCc',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['createSequenceEmail'],
                        },
                    },
                    default: '',
                    placeholder: 'team@example.com',
                    description: 'Optional CC header value for the email template',
                },
                {
                    displayName: 'BCC',
                    name: 'createSequenceEmailBcc',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['createSequenceEmail'],
                        },
                    },
                    default: '',
                    placeholder: 'audit@example.com',
                    description: 'Optional BCC header value for the email template',
                },
                {
                    displayName: 'Page',
                    name: 'listWorkflowsPage',
                    type: 'number',
                    typeOptions: {
                        minValue: 1,
                    },
                    displayOptions: {
                        show: {
                            operation: ['listWorkflows'],
                        },
                    },
                    default: 1,
                    description: 'Page number of workflows to retrieve',
                },
                {
                    displayName: 'Template ID',
                    name: 'emailTemplateId',
                    type: 'number',
                    typeOptions: {
                        minValue: 1,
                    },
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['getEmailTemplate', 'updateEmailTemplate'],
                        },
                    },
                    default: 1,
                    description: 'Numeric identifier of the Bento email template',
                },
                {
                    displayName: 'Subject',
                    name: 'updateEmailTemplateSubject',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['updateEmailTemplate'],
                        },
                    },
                    default: '',
                    placeholder: 'Updated subject line',
                    description: 'Optional replacement subject line for the email template',
                },
                {
                    displayName: 'HTML',
                    name: 'updateEmailTemplateHtml',
                    type: 'string',
                    typeOptions: {
                        rows: 8,
                    },
                    displayOptions: {
                        show: {
                            operation: ['updateEmailTemplate'],
                        },
                    },
                    default: '',
                    placeholder: '<p>Updated HTML content</p>',
                    description: 'Optional replacement HTML for the email template',
                },
                {
                    displayName: 'Field Key',
                    name: 'createFieldKey',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['createField'],
                        },
                    },
                    default: '',
                    placeholder: 'company',
                    description: 'Unique field key to create in Bento',
                },
                {
                    displayName: 'Tag Name',
                    name: 'createTagName',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['createTag'],
                        },
                    },
                    default: '',
                    placeholder: 'vip_customer',
                    description: 'Name of the Bento tag to create',
                },
                {
                    displayName: 'User ID',
                    name: 'userId',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['trackEvent'],
                        },
                    },
                    default: '',
                    placeholder: 'user123@example.com',
                    description: 'The unique identifier for the user (typically email address)',
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
                {
                    displayName: 'Recipient Email',
                    name: 'recipientEmail',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['sendTransactionalEmail'],
                        },
                    },
                    default: '',
                    placeholder: 'recipient@example.com',
                    description: 'The email address of the recipient',
                },
                {
                    displayName: 'From Email',
                    name: 'fromEmail',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['sendTransactionalEmail'],
                        },
                    },
                    default: '',
                    placeholder: 'noreply@yourcompany.com',
                    description: 'The sender email address',
                },
                {
                    displayName: 'Subject',
                    name: 'subject',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['sendTransactionalEmail'],
                        },
                    },
                    default: '',
                    placeholder: 'Reset Password',
                    description: 'Email subject line',
                },
                {
                    displayName: 'Email Type',
                    name: 'emailType',
                    type: 'options',
                    displayOptions: {
                        show: {
                            operation: ['sendTransactionalEmail'],
                        },
                    },
                    options: [
                        {
                            name: 'HTML Body',
                            value: 'html',
                            description: 'Send HTML formatted email',
                        },
                        {
                            name: 'Text Body',
                            value: 'text',
                            description: 'Send plain text email',
                        },
                    ],
                    default: 'html',
                    description: 'Type of email body to send',
                },
                {
                    displayName: 'HTML Body',
                    name: 'htmlBody',
                    type: 'string',
                    typeOptions: {
                        rows: 8,
                    },
                    displayOptions: {
                        show: {
                            operation: ['sendTransactionalEmail'],
                            emailType: ['html'],
                        },
                    },
                    default: '',
                    placeholder: '<p>Here is a link to reset your password ... {{ link }}</p>',
                    description: 'HTML content of the email (supports template variables like {{ variable_name }})',
                },
                {
                    displayName: 'Text Body',
                    name: 'textBody',
                    type: 'string',
                    typeOptions: {
                        rows: 8,
                    },
                    displayOptions: {
                        show: {
                            operation: ['sendTransactionalEmail'],
                            emailType: ['text'],
                        },
                    },
                    default: '',
                    placeholder: 'Here is a link to reset your password ... {{ link }}',
                    description: 'Plain text content of the email (supports template variables like {{ variable_name }})',
                },
                {
                    displayName: 'Transactional',
                    name: 'transactional',
                    type: 'boolean',
                    displayOptions: {
                        show: {
                            operation: ['sendTransactionalEmail'],
                        },
                    },
                    default: false,
                    description: 'Whether this is a transactional email (affects tracking and analytics)',
                },
                {
                    displayName: 'Personalizations',
                    name: 'personalizations',
                    type: 'fixedCollection',
                    typeOptions: {
                        multipleValues: true,
                    },
                    displayOptions: {
                        show: {
                            operation: ['sendTransactionalEmail'],
                        },
                    },
                    default: {},
                    options: [
                        {
                            name: 'personalization',
                            displayName: 'Personalization',
                            values: [
                                {
                                    displayName: 'Key',
                                    name: 'key',
                                    type: 'string',
                                    default: '',
                                    placeholder: 'link',
                                    description: 'Template variable name (without {{ }})',
                                },
                                {
                                    displayName: 'Value',
                                    name: 'value',
                                    type: 'string',
                                    default: '',
                                    placeholder: 'https://example.com/reset',
                                    description: 'Value to substitute in template',
                                },
                            ],
                        },
                    ],
                    description: 'Template variables to personalize the email (e.g., link, first_name, order_total)',
                },
                {
                    displayName: 'Email',
                    name: 'commandEmail',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['subscriberCommand'],
                        },
                    },
                    default: '',
                    placeholder: 'user@example.com',
                    description: 'The email address of the subscriber to execute the command on',
                },
                {
                    displayName: 'Command',
                    name: 'command',
                    type: 'options',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['subscriberCommand'],
                        },
                    },
                    options: [
                        {
                            name: 'Add Field',
                            value: 'add_field',
                            description: 'Add a custom field to the subscriber',
                        },
                        {
                            name: 'Add Tag',
                            value: 'add_tag',
                            description: 'Add a tag to the subscriber',
                        },
                        {
                            name: 'Add Tag via Event',
                            value: 'add_tag_via_event',
                            description: 'Add a tag to the subscriber via event',
                        },
                        {
                            name: 'Change Email',
                            value: 'change_email',
                            description: 'Change the email address of the subscriber',
                        },
                        {
                            name: 'Remove Field',
                            value: 'remove_field',
                            description: 'Remove a custom field from the subscriber',
                        },
                        {
                            name: 'Remove Tag',
                            value: 'remove_tag',
                            description: 'Remove a tag from the subscriber',
                        },
                        {
                            name: 'Subscribe',
                            value: 'subscribe',
                            description: 'Subscribe the email address',
                        },
                        {
                            name: 'Unsubscribe',
                            value: 'unsubscribe',
                            description: 'Unsubscribe the email address',
                        },
                    ],
                    default: 'add_tag',
                    description: 'The command to execute on the subscriber',
                },
                {
                    displayName: 'Tag/Field Name',
                    name: 'query',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['subscriberCommand'],
                            command: ['add_tag', 'add_tag_via_event', 'remove_tag', 'remove_field'],
                        },
                    },
                    default: '',
                    placeholder: 'vip_customer',
                    description: 'The name of the tag or field to add/remove',
                },
                {
                    displayName: 'Field Key',
                    name: 'fieldKey',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['subscriberCommand'],
                            command: ['add_field'],
                        },
                    },
                    default: '',
                    placeholder: 'company',
                    description: 'The key/name of the custom field',
                },
                {
                    displayName: 'Field Value',
                    name: 'fieldValue',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['subscriberCommand'],
                            command: ['add_field'],
                        },
                    },
                    default: '',
                    placeholder: 'Acme Corp',
                    description: 'The value of the custom field',
                },
                {
                    displayName: 'New Email',
                    name: 'newEmail',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['subscriberCommand'],
                            command: ['change_email'],
                        },
                    },
                    default: '',
                    placeholder: 'newemail@example.com',
                    description: 'The new email address for the subscriber',
                },
                {
                    displayName: 'Email',
                    name: 'validateEmail',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['validateEmail'],
                        },
                    },
                    default: '',
                    placeholder: 'test@example.com',
                    description: 'The email address to validate',
                },
                {
                    displayName: 'Name',
                    name: 'validateName',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['validateEmail'],
                        },
                    },
                    default: '',
                    placeholder: 'John Doe',
                    description: 'The name associated with the email (optional but recommended for better validation)',
                },
                {
                    displayName: 'IP Address',
                    name: 'validateIp',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['validateEmail'],
                        },
                    },
                    default: '',
                    placeholder: '1.1.1.1',
                    description: 'The IP address associated with the email (optional but recommended for better validation)',
                },
                {
                    displayName: 'Domain',
                    name: 'blacklistDomain',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['blacklistCheck'],
                        },
                    },
                    default: '',
                    placeholder: 'test.com',
                    description: 'Domain to evaluate against Bento\'s blacklist service. Provide either a domain, an IP, or both.',
                },
                {
                    displayName: 'IP Address',
                    name: 'blacklistIp',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['blacklistCheck'],
                        },
                    },
                    default: '',
                    placeholder: '123.45.67.89',
                    description: 'Optional IP address to evaluate. Provide either an IP, a domain, or both.',
                },
                {
                    displayName: 'Content',
                    name: 'moderationContent',
                    type: 'string',
                    typeOptions: {
                        rows: 6,
                    },
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['contentModeration'],
                        },
                    },
                    default: '',
                    placeholder: 'Message text to evaluate...',
                    description: 'Content that should be evaluated by Bento\'s moderation service',
                },
                {
                    displayName: 'Metadata',
                    name: 'moderationMetadata',
                    type: 'fixedCollection',
                    typeOptions: {
                        multipleValues: true,
                    },
                    displayOptions: {
                        show: {
                            operation: ['contentModeration'],
                        },
                    },
                    default: {},
                    description: 'Optional metadata to provide additional context for moderation (key/value pairs)',
                    options: [
                        {
                            name: 'metadata',
                            displayName: 'Metadata',
                            values: [
                                {
                                    displayName: 'Key',
                                    name: 'key',
                                    type: 'string',
                                    default: '',
                                    placeholder: 'source',
                                },
                                {
                                    displayName: 'Value',
                                    name: 'value',
                                    type: 'string',
                                    default: '',
                                    placeholder: 'contact_form',
                                },
                            ],
                        },
                    ],
                },
                {
                    displayName: 'Email',
                    name: 'genderGuessEmail',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['genderGuess'],
                        },
                    },
                    default: '',
                    placeholder: 'subscriber@example.com',
                    description: 'Email address associated with the person (optional but improves accuracy)',
                },
                {
                    displayName: 'First Name',
                    name: 'genderGuessFirstName',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['genderGuess'],
                        },
                    },
                    default: '',
                    description: 'First name to help the gender guess service',
                },
                {
                    displayName: 'Last Name',
                    name: 'genderGuessLastName',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['genderGuess'],
                        },
                    },
                    default: '',
                    description: 'Last name to help the gender guess service',
                },
                {
                    displayName: 'IP Address',
                    name: 'geolocationIp',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['geolocationLookup'],
                        },
                    },
                    default: '',
                    placeholder: '203.0.113.42',
                    description: 'IP address to look up',
                },
                {
                    displayName: 'User Agent',
                    name: 'geolocationUserAgent',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['geolocationLookup'],
                        },
                    },
                    default: '',
                    description: 'Optional user agent string for additional context',
                },
                {
                    displayName: 'Segment ID',
                    name: 'segmentStatsSegmentId',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['segmentStats'],
                        },
                    },
                    default: '',
                    placeholder: 'seg_12345',
                    description: 'Unique identifier of the Bento segment to analyze',
                },
                {
                    displayName: 'Report ID',
                    name: 'reportStatsReportId',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['reportStats'],
                        },
                    },
                    default: '',
                    placeholder: '456',
                    description: 'Identifier of the Bento report (report_id) to fetch metrics for',
                },
                {
                    displayName: 'Status',
                    name: 'listBroadcastsStatus',
                    type: 'options',
                    noDataExpression: true,
                    displayOptions: {
                        show: {
                            operation: ['listBroadcasts'],
                        },
                    },
                    options: [
                        {
                            name: 'Any',
                            value: 'any',
                        },
                        {
                            name: 'Archived',
                            value: 'archived',
                        },
                        {
                            name: 'Draft',
                            value: 'draft',
                        },
                        {
                            name: 'Scheduled',
                            value: 'scheduled',
                        },
                        {
                            name: 'Sending',
                            value: 'sending',
                        },
                        {
                            name: 'Sent',
                            value: 'sent',
                        },
                    ],
                    default: 'any',
                    description: 'Filter broadcasts by status',
                },
                {
                    displayName: 'Created After',
                    name: 'listBroadcastsCreatedAfter',
                    type: 'dateTime',
                    displayOptions: {
                        show: {
                            operation: ['listBroadcasts'],
                        },
                    },
                    default: '',
                    description: 'Return broadcasts created after this date',
                },
                {
                    displayName: 'Tag IDs',
                    name: 'listBroadcastsTagIds',
                    type: 'fixedCollection',
                    typeOptions: {
                        multipleValues: true,
                    },
                    displayOptions: {
                        show: {
                            operation: ['listBroadcasts'],
                        },
                    },
                    default: {},
                    description: 'Filter broadcasts linked to specific tag IDs',
                    options: [
                        {
                            name: 'tagId',
                            displayName: 'Tag ID',
                            values: [
                                {
                                    displayName: 'Tag ID',
                                    name: 'id',
                                    type: 'string',
                                    default: '',
                                    placeholder: 'tag_12345',
                                },
                            ],
                        },
                    ],
                },
                {
                    displayName: 'Campaign Name',
                    name: 'sendBroadcastName',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    default: '',
                    placeholder: 'Campaign #1 — Plain Text Example',
                    description: 'Name to assign to the broadcast campaign',
                },
                {
                    displayName: 'Subject',
                    name: 'sendBroadcastSubject',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    default: '',
                    placeholder: 'Hello Plain World',
                    description: 'Email subject line',
                },
                {
                    displayName: 'Content',
                    name: 'sendBroadcastContent',
                    type: 'string',
                    typeOptions: {
                        rows: 5,
                    },
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    default: '',
                    description: 'Email content (plain text or HTML based on Content Type)',
                },
                {
                    displayName: 'Content Type',
                    name: 'sendBroadcastType',
                    type: 'options',
                    noDataExpression: true,
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    options: [
                        {
                            name: 'Plain Text',
                            value: 'plain',
                        },
                        {
                            name: 'HTML',
                            value: 'html',
                        },
                    ],
                    default: 'plain',
                    description: 'Render the campaign as plain text or HTML',
                },
                {
                    displayName: 'From Email',
                    name: 'sendBroadcastFromEmail',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    default: '',
                    placeholder: 'example@example.com',
                    description: 'Email address shown to recipients',
                },
                {
                    displayName: 'From Name',
                    name: 'sendBroadcastFromName',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    default: '',
                    placeholder: 'John Doe',
                    description: 'Display name shown to recipients',
                },
                {
                    displayName: 'Approved',
                    name: 'sendBroadcastApproved',
                    type: 'boolean',
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    default: false,
                    description: 'Whether to mark the broadcast as approved for sending',
                },
                {
                    displayName: 'Inclusive Tags',
                    name: 'sendBroadcastInclusiveTags',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    default: '',
                    placeholder: 'lead,mql',
                    description: 'Comma-separated tags to include in the audience',
                },
                {
                    displayName: 'Exclusive Tags',
                    name: 'sendBroadcastExclusiveTags',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    default: '',
                    placeholder: 'customers',
                    description: 'Comma-separated tags to exclude from the audience',
                },
                {
                    displayName: 'Segment ID',
                    name: 'sendBroadcastSegmentId',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    default: '',
                    placeholder: 'segment_123456789',
                    description: 'Segment identifier to restrict the broadcast (optional)',
                },
                {
                    displayName: 'Batch Size Per Hour',
                    name: 'sendBroadcastBatchSizePerHour',
                    type: 'number',
                    typeOptions: {
                        minValue: 1,
                    },
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    default: 0,
                    description: 'Optional hourly batch size limit (leave at 0 to use Bento defaults)',
                },
                {
                    displayName: 'Confirm Send',
                    name: 'sendBroadcastConfirm',
                    type: 'boolean',
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    default: false,
                    description: 'Whether to confirm sending this broadcast',
                },
            ],
        };
    }
    async execute() {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t, _u, _v, _w, _x, _y, _z, _0, _1, _2, _3, _4, _5;
        const items = this.getInputData();
        const returnData = [];
        for (let i = 0; i < items.length; i++) {
            try {
                const operation = this.getNodeParameter('operation', i);
                let responseData;
                switch (operation) {
                    case 'createField': {
                        const fieldKey = (this.getNodeParameter('createFieldKey', i) || '').trim();
                        validateInputLength.call(this, fieldKey, INPUT_LIMITS.CUSTOM_FIELD_KEY, 'Field Key', i);
                        if (!fieldKey) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Field key is required for field creation', {
                                itemIndex: i,
                            });
                        }
                        try {
                            const response = await makeBentoRequest.call(this, 'POST', '/api/v1/fetch/fields', {
                                field: {
                                    key: fieldKey,
                                },
                            }, i);
                            responseData = {
                                operation: 'createField',
                                success: true,
                                fieldKey,
                                fields: Array.isArray(response === null || response === void 0 ? void 0 : response.data) ? response.data : undefined,
                                apiResponse: response,
                                message: 'Field created successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'createField', { itemIndex: i });
                            responseData = {
                                operation: 'createField',
                                success: false,
                                fieldKey: fieldKey || undefined,
                                error: createSecureErrorMessage(error, 'createField'),
                                message: 'Failed to create field. Check the field key and credentials, then try again.',
                            };
                        }
                        break;
                    }
                    case 'createSequenceEmail': {
                        const sequenceId = (this.getNodeParameter('createSequenceEmailSequenceId', i) || '').trim();
                        const subject = (this.getNodeParameter('createSequenceEmailSubject', i) || '').trim();
                        const htmlInput = this.getNodeParameter('createSequenceEmailHtml', i) || '';
                        const inboxSnippet = (this.getNodeParameter('createSequenceEmailInboxSnippet', i) || '').trim();
                        const delayInterval = this.getNodeParameter('createSequenceEmailDelayInterval', i) || '';
                        const delayIntervalCount = this.getNodeParameter('createSequenceEmailDelayIntervalCount', i);
                        const editorChoice = (this.getNodeParameter('createSequenceEmailEditorChoice', i) || '').trim();
                        const to = (this.getNodeParameter('createSequenceEmailTo', i) || '').trim();
                        const cc = (this.getNodeParameter('createSequenceEmailCc', i) || '').trim();
                        const bcc = (this.getNodeParameter('createSequenceEmailBcc', i) || '').trim();
                        validateInputLength.call(this, sequenceId, INPUT_LIMITS.RESOURCE_ID, 'Sequence ID', i);
                        validateInputLength.call(this, subject, INPUT_LIMITS.SUBJECT, 'Subject', i);
                        validateInputLength.call(this, htmlInput, INPUT_LIMITS.HTML_CONTENT, 'HTML', i);
                        validateInputLength.call(this, inboxSnippet, INPUT_LIMITS.INBOX_SNIPPET, 'Inbox Snippet', i);
                        validateInputLength.call(this, editorChoice, INPUT_LIMITS.VALIDATE_NAME, 'Editor Choice', i);
                        validateInputLength.call(this, to, INPUT_LIMITS.CUSTOM_FIELD_VALUE, 'To', i);
                        validateInputLength.call(this, cc, INPUT_LIMITS.CUSTOM_FIELD_VALUE, 'CC', i);
                        validateInputLength.call(this, bcc, INPUT_LIMITS.CUSTOM_FIELD_VALUE, 'BCC', i);
                        if (!sequenceId) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Sequence ID is required for creating a sequence email', {
                                itemIndex: i,
                            });
                        }
                        if (!subject) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Subject is required for creating a sequence email', {
                                itemIndex: i,
                            });
                        }
                        if (!htmlInput.trim()) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'HTML is required for creating a sequence email', {
                                itemIndex: i,
                            });
                        }
                        const html = sanitizeTemplateHtmlContent(htmlInput);
                        if (!html) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'HTML is empty after sanitization', {
                                itemIndex: i,
                            });
                        }
                        if (!validateTemplateHtmlContent(html)) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'HTML contains unsupported or unsafe content', {
                                itemIndex: i,
                            });
                        }
                        const emailTemplatePayload = {
                            subject,
                            html,
                        };
                        if (inboxSnippet) {
                            emailTemplatePayload.inbox_snippet = inboxSnippet;
                        }
                        if (delayInterval) {
                            emailTemplatePayload.delay_interval = delayInterval;
                            emailTemplatePayload.delay_interval_count = validatePositiveIntegerInput.call(this, delayIntervalCount, 'Delay Interval Count', i);
                        }
                        if (editorChoice) {
                            emailTemplatePayload.editor_choice = editorChoice;
                        }
                        if (to) {
                            emailTemplatePayload.to = to;
                        }
                        if (cc) {
                            emailTemplatePayload.cc = cc;
                        }
                        if (bcc) {
                            emailTemplatePayload.bcc = bcc;
                        }
                        try {
                            const response = await makeBentoRequest.call(this, 'POST', `/api/v1/fetch/sequences/${encodeURIComponent(sequenceId)}/emails/templates`, {
                                email_template: emailTemplatePayload,
                            }, i);
                            responseData = {
                                operation: 'createSequenceEmail',
                                success: true,
                                sequenceId,
                                emailTemplate: (_a = response === null || response === void 0 ? void 0 : response.data) !== null && _a !== void 0 ? _a : response,
                                apiResponse: response,
                                message: 'Sequence email created successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'createSequenceEmail', { itemIndex: i });
                            responseData = {
                                operation: 'createSequenceEmail',
                                success: false,
                                sequenceId: sequenceId || undefined,
                                error: createSecureErrorMessage(error, 'createSequenceEmail'),
                                message: 'Failed to create sequence email. Review the sequence ID and template fields, then try again.',
                            };
                        }
                        break;
                    }
                    case 'createSubscriber': {
                        const email = sanitizeEmail(this.getNodeParameter('email', i));
                        const firstName = this.getNodeParameter('firstName', i);
                        const lastName = this.getNodeParameter('lastName', i);
                        const customFields = this.getNodeParameter('customFields', i);
                        validateInputLength.call(this, email, INPUT_LIMITS.EMAIL, 'Email', i);
                        validateInputLength.call(this, firstName, INPUT_LIMITS.NAME, 'First Name', i);
                        validateInputLength.call(this, lastName, INPUT_LIMITS.NAME, 'Last Name', i);
                        if (!email) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Email is required for creating a subscriber', {
                                itemIndex: i,
                            });
                        }
                        if (!isValidEmail(email)) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid email format', {
                                itemIndex: i,
                            });
                        }
                        const details = {
                            first_name: firstName || '',
                            last_name: lastName || '',
                        };
                        if (customFields.field) {
                            for (const field of customFields.field) {
                                if (field.key && field.value) {
                                    validateInputLength.call(this, field.key, INPUT_LIMITS.CUSTOM_FIELD_KEY, 'Custom Field Key', i);
                                    validateInputLength.call(this, field.value, INPUT_LIMITS.CUSTOM_FIELD_VALUE, 'Custom Field Value', i);
                                    details[field.key] = field.value;
                                }
                            }
                        }
                        const requestBody = {
                            events: [
                                {
                                    email: email,
                                    type: '$subscribe',
                                    details: details
                                }
                            ]
                        };
                        try {
                            const response = await makeBentoRequest.call(this, 'POST', '/api/v1/batch/events', requestBody, i);
                            responseData = {
                                operation: 'createSubscriber',
                                success: true,
                                subscriber: {
                                    email,
                                    firstName,
                                    lastName,
                                },
                                apiResponse: response,
                                message: 'Subscriber created successfully using Events API',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'createSubscriber', { itemIndex: i });
                            responseData = {
                                operation: 'createSubscriber',
                                success: false,
                                subscriber: {
                                    email: email ? '[REDACTED]' : undefined,
                                    firstName,
                                    lastName,
                                },
                                error: createSecureErrorMessage(error, 'createSubscriber'),
                                message: 'Failed to create subscriber. Please check your credentials and input data.',
                            };
                        }
                        break;
                    }
                    case 'createTag': {
                        const tagName = (this.getNodeParameter('createTagName', i) || '').trim();
                        validateInputLength.call(this, tagName, INPUT_LIMITS.TAG_NAME, 'Tag Name', i);
                        if (!tagName) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Tag name is required for tag creation', {
                                itemIndex: i,
                            });
                        }
                        try {
                            const response = await makeBentoRequest.call(this, 'POST', '/api/v1/fetch/tags', {
                                tag: {
                                    name: tagName,
                                },
                            }, i);
                            responseData = {
                                operation: 'createTag',
                                success: true,
                                tagName,
                                tags: Array.isArray(response === null || response === void 0 ? void 0 : response.data) ? response.data : undefined,
                                apiResponse: response,
                                message: 'Tag created successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'createTag', { itemIndex: i });
                            responseData = {
                                operation: 'createTag',
                                success: false,
                                tagName: tagName || undefined,
                                error: createSecureErrorMessage(error, 'createTag'),
                                message: 'Failed to create tag. Check the tag name and credentials, then try again.',
                            };
                        }
                        break;
                    }
                    case 'getEmailTemplate': {
                        const templateId = validatePositiveIntegerInput.call(this, this.getNodeParameter('emailTemplateId', i), 'Template ID', i);
                        try {
                            const response = await makeBentoRequest.call(this, 'GET', `/api/v1/fetch/emails/templates/${templateId}`, undefined, i);
                            responseData = {
                                operation: 'getEmailTemplate',
                                success: true,
                                templateId,
                                emailTemplate: (_b = response === null || response === void 0 ? void 0 : response.data) !== null && _b !== void 0 ? _b : response,
                                apiResponse: response,
                                message: 'Email template retrieved successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'getEmailTemplate', { itemIndex: i });
                            responseData = {
                                operation: 'getEmailTemplate',
                                success: false,
                                templateId,
                                error: createSecureErrorMessage(error, 'getEmailTemplate'),
                                message: 'Failed to retrieve email template. Verify the template ID and try again.',
                            };
                        }
                        break;
                    }
                    case 'getSubscriber': {
                        const email = sanitizeEmail(this.getNodeParameter('email', i));
                        validateInputLength.call(this, email, INPUT_LIMITS.EMAIL, 'Email', i);
                        if (!email) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Email is required for getting subscriber information', {
                                itemIndex: i,
                            });
                        }
                        if (!isValidEmail(email)) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid email format', {
                                itemIndex: i,
                            });
                        }
                        try {
                            const response = await makeBentoRequest.call(this, 'GET', `/api/v1/fetch/subscribers?email=${encodeURIComponent(email)}`, undefined, i);
                            responseData = {
                                operation: 'getSubscriber',
                                success: true,
                                email,
                                subscriber: response,
                                apiResponse: response,
                                message: 'Subscriber retrieved successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'getSubscriber', { itemIndex: i });
                            responseData = {
                                operation: 'getSubscriber',
                                success: false,
                                email: email ? '[REDACTED]' : undefined,
                                error: createSecureErrorMessage(error, 'getSubscriber'),
                                message: 'Failed to retrieve subscriber. Please check your credentials and email address.',
                            };
                        }
                        break;
                    }
                    case 'updateSubscriber': {
                        const email = sanitizeEmail(this.getNodeParameter('email', i));
                        const firstName = this.getNodeParameter('firstName', i);
                        const lastName = this.getNodeParameter('lastName', i);
                        const customFields = this.getNodeParameter('customFields', i);
                        validateInputLength.call(this, email, INPUT_LIMITS.EMAIL, 'Email', i);
                        validateInputLength.call(this, firstName, INPUT_LIMITS.NAME, 'First Name', i);
                        validateInputLength.call(this, lastName, INPUT_LIMITS.NAME, 'Last Name', i);
                        if (!email) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Email is required for updating a subscriber', {
                                itemIndex: i,
                            });
                        }
                        if (!isValidEmail(email)) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid email format', {
                                itemIndex: i,
                            });
                        }
                        const subscriberData = {
                            email: email,
                            first_name: firstName || '',
                            last_name: lastName || '',
                        };
                        if (customFields.field) {
                            for (const field of customFields.field) {
                                if (field.key && field.value) {
                                    validateInputLength.call(this, field.key, INPUT_LIMITS.CUSTOM_FIELD_KEY, 'Custom Field Key', i);
                                    validateInputLength.call(this, field.value, INPUT_LIMITS.CUSTOM_FIELD_VALUE, 'Custom Field Value', i);
                                    subscriberData[field.key] = field.value;
                                }
                            }
                        }
                        const requestBody = {
                            subscribers: [subscriberData]
                        };
                        try {
                            const response = await makeBentoRequest.call(this, 'POST', '/api/v1/batch/subscribers', requestBody, i);
                            responseData = {
                                operation: 'updateSubscriber',
                                success: true,
                                subscriber: {
                                    email,
                                    firstName,
                                    lastName,
                                },
                                apiResponse: response,
                                message: 'Subscriber updated successfully using Import Subscribers API',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'updateSubscriber', { itemIndex: i });
                            responseData = {
                                operation: 'updateSubscriber',
                                success: false,
                                subscriber: {
                                    email: email ? '[REDACTED]' : undefined,
                                    firstName,
                                    lastName,
                                },
                                error: createSecureErrorMessage(error, 'updateSubscriber'),
                                message: 'Failed to update subscriber. Please check your credentials and input data.',
                            };
                        }
                        break;
                    }
                    case 'trackEvent': {
                        const userId = this.getNodeParameter('userId', i);
                        const eventName = this.getNodeParameter('eventName', i);
                        const eventProperties = this.getNodeParameter('eventProperties', i);
                        validateInputLength.call(this, userId, INPUT_LIMITS.USER_ID, 'User ID', i);
                        validateInputLength.call(this, eventName, INPUT_LIMITS.EVENT_NAME, 'Event Name', i);
                        if (!userId || !eventName) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'User ID and event name are required for tracking events', {
                                itemIndex: i,
                            });
                        }
                        const properties = {};
                        if (eventProperties.property) {
                            for (const prop of eventProperties.property) {
                                if (prop.key && prop.value) {
                                    validateInputLength.call(this, prop.key, INPUT_LIMITS.EVENT_PROPERTY_KEY, 'Event Property Key', i);
                                    validateInputLength.call(this, prop.value, INPUT_LIMITS.EVENT_PROPERTY_VALUE, 'Event Property Value', i);
                                    properties[prop.key] = prop.value;
                                }
                            }
                        }
                        const requestBody = {
                            events: [
                                {
                                    email: userId,
                                    type: eventName,
                                    details: properties,
                                }
                            ]
                        };
                        try {
                            const response = await makeBentoRequest.call(this, 'POST', '/api/v1/batch/events', requestBody, i);
                            responseData = {
                                operation: 'trackEvent',
                                success: true,
                                event: {
                                    userId,
                                    eventName,
                                    properties,
                                },
                                apiResponse: response,
                                message: 'Event tracked successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'trackEvent', { itemIndex: i });
                            responseData = {
                                operation: 'trackEvent',
                                success: false,
                                event: {
                                    userId: userId ? '[REDACTED]' : undefined,
                                    eventName,
                                    properties: Object.keys(properties).length > 0 ? '[REDACTED]' : {},
                                },
                                error: createSecureErrorMessage(error, 'trackEvent'),
                                message: 'Failed to track event. Please check your credentials and event data.',
                            };
                        }
                        break;
                    }
                    case 'sendTransactionalEmail': {
                        const recipientEmail = sanitizeEmail(this.getNodeParameter('recipientEmail', i));
                        const fromEmail = sanitizeEmail(this.getNodeParameter('fromEmail', i));
                        const subject = this.getNodeParameter('subject', i);
                        const emailType = this.getNodeParameter('emailType', i);
                        const transactional = this.getNodeParameter('transactional', i);
                        const personalizations = this.getNodeParameter('personalizations', i);
                        validateInputLength.call(this, recipientEmail, INPUT_LIMITS.EMAIL, 'Recipient Email', i);
                        validateInputLength.call(this, fromEmail, INPUT_LIMITS.EMAIL, 'From Email', i);
                        validateInputLength.call(this, subject, INPUT_LIMITS.SUBJECT, 'Subject', i);
                        let htmlBody = '';
                        let textBody = '';
                        if (emailType === 'html') {
                            htmlBody = this.getNodeParameter('htmlBody', i);
                            if (htmlBody) {
                                const htmlValidation = validateHtmlStructure(htmlBody);
                                if (!htmlValidation.isValid) {
                                    throw new n8n_workflow_1.NodeOperationError(this.getNode(), `HTML content validation failed: ${htmlValidation.issues.join(', ')}`, { itemIndex: i });
                                }
                                htmlBody = sanitizeHtmlContent(htmlBody);
                            }
                        }
                        else {
                            textBody = this.getNodeParameter('textBody', i);
                        }
                        if (emailType === 'html') {
                            validateInputLength.call(this, htmlBody, INPUT_LIMITS.HTML_CONTENT, 'HTML Body', i);
                        }
                        else {
                            validateInputLength.call(this, textBody, INPUT_LIMITS.TEXT_CONTENT, 'Text Body', i);
                        }
                        if (!recipientEmail || !fromEmail || !subject) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Recipient email, from email, and subject are required for sending transactional emails', {
                                itemIndex: i,
                            });
                        }
                        if (!isValidEmail(recipientEmail)) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid recipient email format', {
                                itemIndex: i,
                            });
                        }
                        if (!isValidEmail(fromEmail)) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid from email format', {
                                itemIndex: i,
                            });
                        }
                        if (emailType === 'html' && !htmlBody) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'HTML body is required when email type is HTML', {
                                itemIndex: i,
                            });
                        }
                        if (emailType === 'text' && !textBody) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Text body is required when email type is Text', {
                                itemIndex: i,
                            });
                        }
                        if (!htmlBody && !textBody) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Either HTML body or Text body is required', {
                                itemIndex: i,
                            });
                        }
                        if (emailType === 'html' && htmlBody) {
                            if (!validateHtmlContent(htmlBody)) {
                                throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'HTML content contains potentially dangerous elements and cannot be sent', { itemIndex: i });
                            }
                        }
                        const personalizationsData = {};
                        if (personalizations.personalization) {
                            for (const item of personalizations.personalization) {
                                if (item.key && item.value) {
                                    if (typeof item.value === 'string' && item.value.includes('<')) {
                                        if (!validateHtmlContent(item.value)) {
                                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), `Personalization value for "${item.key}" contains potentially dangerous HTML content`, { itemIndex: i });
                                        }
                                        personalizationsData[item.key] = sanitizeHtmlContent(item.value);
                                    }
                                    else {
                                        personalizationsData[item.key] = item.value;
                                    }
                                }
                            }
                        }
                        const emailData = {
                            to: recipientEmail,
                            from: fromEmail,
                            subject: subject,
                            transactional: transactional,
                            personalizations: personalizationsData,
                        };
                        if (emailType === 'html') {
                            emailData.html_body = htmlBody;
                        }
                        else {
                            emailData.text_body = textBody;
                        }
                        const requestBody = {
                            emails: [emailData]
                        };
                        try {
                            const response = await makeBentoRequest.call(this, 'POST', '/api/v1/batch/emails', requestBody, i);
                            responseData = {
                                operation: 'sendTransactionalEmail',
                                success: true,
                                email: {
                                    recipient: recipientEmail,
                                    from: fromEmail,
                                    subject: subject,
                                    type: emailType,
                                    transactional: transactional,
                                    personalizations: personalizationsData,
                                },
                                apiResponse: response,
                                message: 'Transactional email sent successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'sendTransactionalEmail', { itemIndex: i });
                            responseData = {
                                operation: 'sendTransactionalEmail',
                                success: false,
                                email: {
                                    recipient: recipientEmail ? '[REDACTED]' : undefined,
                                    from: fromEmail ? '[REDACTED]' : undefined,
                                    subject,
                                    type: emailType,
                                    transactional,
                                },
                                error: createSecureErrorMessage(error, 'sendTransactionalEmail'),
                                message: 'Failed to send email. Please check your credentials and email content.',
                            };
                        }
                        break;
                    }
                    case 'subscriberCommand': {
                        const email = sanitizeEmail(this.getNodeParameter('commandEmail', i));
                        const command = this.getNodeParameter('command', i);
                        validateInputLength.call(this, email, INPUT_LIMITS.EMAIL, 'Email', i);
                        let query = '';
                        let fieldKey = '';
                        let fieldValue = '';
                        let newEmail = '';
                        if (['add_tag', 'add_tag_via_event', 'remove_tag', 'remove_field'].includes(command)) {
                            query = this.getNodeParameter('query', i);
                            validateInputLength.call(this, query, INPUT_LIMITS.CUSTOM_FIELD_KEY, 'Query', i);
                        }
                        if (command === 'add_field') {
                            fieldKey = this.getNodeParameter('fieldKey', i);
                            fieldValue = this.getNodeParameter('fieldValue', i);
                            validateInputLength.call(this, fieldKey, INPUT_LIMITS.CUSTOM_FIELD_KEY, 'Field Key', i);
                            validateInputLength.call(this, fieldValue, INPUT_LIMITS.CUSTOM_FIELD_VALUE, 'Field Value', i);
                        }
                        if (command === 'change_email') {
                            newEmail = sanitizeEmail(this.getNodeParameter('newEmail', i));
                            validateInputLength.call(this, newEmail, INPUT_LIMITS.EMAIL, 'New Email', i);
                        }
                        if (!email) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Email is required for subscriber commands', {
                                itemIndex: i,
                            });
                        }
                        if (!isValidEmail(email)) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid email format', {
                                itemIndex: i,
                            });
                        }
                        const commandObj = {
                            command: command,
                            email: email,
                        };
                        switch (command) {
                            case 'add_tag':
                            case 'add_tag_via_event':
                            case 'remove_tag':
                            case 'remove_field':
                                if (!query) {
                                    throw new n8n_workflow_1.NodeOperationError(this.getNode(), `Query is required for ${command} command`, {
                                        itemIndex: i,
                                    });
                                }
                                commandObj.query = query;
                                break;
                            case 'add_field':
                                if (!fieldKey || !fieldValue) {
                                    throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Field key and value are required for add_field command', {
                                        itemIndex: i,
                                    });
                                }
                                commandObj.query = {
                                    key: fieldKey,
                                    value: fieldValue,
                                };
                                break;
                            case 'change_email':
                                if (!newEmail) {
                                    throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'New email is required for change_email command', {
                                        itemIndex: i,
                                    });
                                }
                                if (!isValidEmail(newEmail)) {
                                    throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid new email format', {
                                        itemIndex: i,
                                    });
                                }
                                commandObj.query = newEmail;
                                break;
                            case 'subscribe':
                            case 'unsubscribe':
                                break;
                            default:
                                throw new n8n_workflow_1.NodeOperationError(this.getNode(), `Unknown command: ${command}`, {
                                    itemIndex: i,
                                });
                        }
                        const requestBody = {
                            command: [commandObj]
                        };
                        try {
                            const response = await makeBentoRequest.call(this, 'POST', '/api/v1/fetch/commands', requestBody, i);
                            responseData = {
                                operation: 'subscriberCommand',
                                success: true,
                                command: command,
                                email: email,
                                query: commandObj.query,
                                apiResponse: response,
                                message: `Subscriber command '${command}' executed successfully`,
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'subscriberCommand', { itemIndex: i });
                            responseData = {
                                operation: 'subscriberCommand',
                                success: false,
                                command: command,
                                email: email ? '[REDACTED]' : undefined,
                                error: createSecureErrorMessage(error, 'subscriberCommand'),
                                message: `Failed to execute command '${command}'. Please check your credentials and parameters.`,
                            };
                        }
                        break;
                    }
                    case 'updateEmailTemplate': {
                        const templateId = validatePositiveIntegerInput.call(this, this.getNodeParameter('emailTemplateId', i), 'Template ID', i);
                        const subject = (this.getNodeParameter('updateEmailTemplateSubject', i) || '').trim();
                        const htmlInput = this.getNodeParameter('updateEmailTemplateHtml', i) || '';
                        validateInputLength.call(this, subject, INPUT_LIMITS.SUBJECT, 'Subject', i);
                        validateInputLength.call(this, htmlInput, INPUT_LIMITS.HTML_CONTENT, 'HTML', i);
                        if (!subject && !htmlInput.trim()) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Provide at least a subject or HTML value to update the email template', {
                                itemIndex: i,
                            });
                        }
                        const updatePayload = {};
                        if (subject) {
                            updatePayload.subject = subject;
                        }
                        if (htmlInput.trim()) {
                            const html = sanitizeTemplateHtmlContent(htmlInput);
                            if (!html) {
                                throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'HTML is empty after sanitization', {
                                    itemIndex: i,
                                });
                            }
                            if (!validateTemplateHtmlContent(html)) {
                                throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'HTML contains unsupported or unsafe content', {
                                    itemIndex: i,
                                });
                            }
                            updatePayload.html = html;
                        }
                        try {
                            const response = await makeBentoRequest.call(this, 'PATCH', `/api/v1/fetch/emails/templates/${templateId}`, {
                                email_template: updatePayload,
                            }, i);
                            responseData = {
                                operation: 'updateEmailTemplate',
                                success: true,
                                templateId,
                                emailTemplate: (_c = response === null || response === void 0 ? void 0 : response.data) !== null && _c !== void 0 ? _c : response,
                                apiResponse: response,
                                message: 'Email template updated successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'updateEmailTemplate', { itemIndex: i });
                            responseData = {
                                operation: 'updateEmailTemplate',
                                success: false,
                                templateId,
                                error: createSecureErrorMessage(error, 'updateEmailTemplate'),
                                message: 'Failed to update email template. Review the template ID and provided fields, then try again.',
                            };
                        }
                        break;
                    }
                    case 'validateEmail': {
                        const email = sanitizeEmail(this.getNodeParameter('validateEmail', i));
                        const name = this.getNodeParameter('validateName', i);
                        const ip = this.getNodeParameter('validateIp', i);
                        validateInputLength.call(this, email, INPUT_LIMITS.EMAIL, 'Email', i);
                        if (name)
                            validateInputLength.call(this, name, INPUT_LIMITS.VALIDATE_NAME, 'Name', i);
                        if (ip)
                            validateInputLength.call(this, ip, INPUT_LIMITS.IP_ADDRESS, 'IP Address', i);
                        if (!email) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Email is required for validation', {
                                itemIndex: i,
                            });
                        }
                        if (!isValidEmail(email)) {
                            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid email format', {
                                itemIndex: i,
                            });
                        }
                        const queryParams = new URLSearchParams();
                        queryParams.append('email', email);
                        if (name) {
                            queryParams.append('name', name);
                        }
                        if (ip) {
                            queryParams.append('ip', ip);
                        }
                        try {
                            const response = await makeBentoRequest.call(this, 'POST', `/api/v1/experimental/validation?${queryParams.toString()}`, undefined, i);
                            responseData = {
                                operation: 'validateEmail',
                                success: true,
                                email,
                                name: name || undefined,
                                ip: ip || undefined,
                                validation: response,
                                apiResponse: response,
                                message: 'Email validation completed successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'validateEmail', { itemIndex: i });
                            responseData = {
                                operation: 'validateEmail',
                                success: false,
                                email: email ? '[REDACTED]' : undefined,
                                error: createSecureErrorMessage(error, 'validateEmail'),
                                message: 'Failed to validate email. Please check your credentials and email address.',
                            };
                        }
                        break;
                    }
                    case 'blacklistCheck': {
                        const domainInput = this.getNodeParameter('blacklistDomain', i);
                        const ipInput = this.getNodeParameter('blacklistIp', i);
                        const trimmedDomainRaw = typeof domainInput === 'string' ? domainInput.trim() : '';
                        const trimmedIp = typeof ipInput === 'string' ? ipInput.trim() : '';
                        const trimmedDomain = trimmedDomainRaw.toLowerCase();
                        const hasDomain = trimmedDomainRaw !== '';
                        const hasIp = trimmedIp !== '';
                        try {
                            if (!hasDomain && !hasIp) {
                                throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Provide at least a domain or an IP address for blacklist checks', {
                                    itemIndex: i,
                                });
                            }
                            if (hasDomain && trimmedDomain.length > 253) {
                                throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Domain exceeds maximum length of 253 characters', {
                                    itemIndex: i,
                                });
                            }
                            if (hasDomain) {
                                const domainPattern = /^(?!-)(?:[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[A-Za-z]{2,}$/;
                                if (!domainPattern.test(trimmedDomain)) {
                                    throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Domain format is invalid', {
                                        itemIndex: i,
                                    });
                                }
                            }
                            if (trimmedIp) {
                                validateInputLength.call(this, trimmedIp, INPUT_LIMITS.IP_ADDRESS, 'IP Address', i);
                            }
                            const params = new URLSearchParams();
                            if (hasDomain) {
                                params.append('domain', trimmedDomain);
                            }
                            if (trimmedIp) {
                                params.append('ip', trimmedIp);
                            }
                            const endpoint = `/api/v1/experimental/blacklist?${params.toString()}`;
                            const apiResponse = await makeBentoRequest.call(this, 'GET', endpoint, undefined, i);
                            responseData = {
                                operation: 'blacklistCheck',
                                success: true,
                                domain: hasDomain ? trimmedDomain : undefined,
                                ip: trimmedIp || undefined,
                                apiResponse,
                                message: 'Blacklist check completed successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'blacklistCheck', { itemIndex: i });
                            responseData = {
                                operation: 'blacklistCheck',
                                success: false,
                                domain: hasDomain ? trimmedDomain : undefined,
                                ip: trimmedIp || undefined,
                                error: createSecureErrorMessage(error, 'blacklistCheck'),
                                message: 'Failed to run blacklist check. Please verify the domain and try again.',
                            };
                        }
                        break;
                    }
                    case 'contentModeration': {
                        const content = this.getNodeParameter('moderationContent', i);
                        const metadataCollection = this.getNodeParameter('moderationMetadata', i);
                        try {
                            const initialContext = {
                                itemIndex: i,
                                content,
                                metadataPairs: (_d = metadataCollection === null || metadataCollection === void 0 ? void 0 : metadataCollection.metadata) !== null && _d !== void 0 ? _d : [],
                            };
                            const context = await runPipeline(this, initialContext, [
                                validateContentModerationAction,
                                buildContentModerationPayloadAction,
                                executeContentModerationRequestAction,
                            ]);
                            responseData = {
                                operation: 'contentModeration',
                                success: true,
                                apiResponse: context.response,
                                contentEvaluated: context.content,
                                metadata: Object.keys(context.metadata || {}).length ? context.metadata : undefined,
                                message: 'Content moderation completed successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'contentModeration', { itemIndex: i });
                            responseData = {
                                operation: 'contentModeration',
                                success: false,
                                content: content ? '[REDACTED]' : undefined,
                                error: createSecureErrorMessage(error, 'contentModeration'),
                                message: 'Failed to evaluate content. Please review the content and try again.',
                            };
                        }
                        break;
                    }
                    case 'genderGuess': {
                        const emailInput = this.getNodeParameter('genderGuessEmail', i);
                        const requestEmail = typeof emailInput === 'string' ? emailInput.trim() : '';
                        const email = sanitizeEmail(emailInput);
                        const firstNameInput = this.getNodeParameter('genderGuessFirstName', i);
                        const lastNameInput = this.getNodeParameter('genderGuessLastName', i);
                        const firstName = typeof firstNameInput === 'string' ? firstNameInput.trim() : '';
                        const lastName = typeof lastNameInput === 'string' ? lastNameInput.trim() : '';
                        const combinedName = [firstName, lastName].filter(Boolean).join(' ').trim();
                        try {
                            const initialContext = {
                                itemIndex: i,
                                email,
                                requestEmail: requestEmail || undefined,
                                firstName: firstName || undefined,
                                lastName: lastName || undefined,
                                fullName: combinedName || undefined,
                            };
                            const context = await runPipeline(this, initialContext, [
                                validateGenderGuessAction,
                                buildGenderGuessPayloadAction,
                                executeGenderGuessRequestAction,
                            ]);
                            responseData = {
                                operation: 'genderGuess',
                                success: true,
                                email: context.email || requestEmail || undefined,
                                name: context.fullName || undefined,
                                firstName: context.firstName || undefined,
                                lastName: context.lastName || undefined,
                                apiResponse: context.response,
                                summary: ((_e = context.response) === null || _e === void 0 ? void 0 : _e.prediction)
                                    ? {
                                        gender: context.response.prediction,
                                        confidence: context.response.confidence,
                                    }
                                    : undefined,
                                message: 'Gender guess completed successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'genderGuess', { itemIndex: i });
                            responseData = {
                                operation: 'genderGuess',
                                success: false,
                                email: requestEmail || email || undefined,
                                name: combinedName || undefined,
                                error: createSecureErrorMessage(error, 'genderGuess'),
                                message: 'Failed to run gender guess. Provide a first and/or last name and try again.',
                            };
                        }
                        break;
                    }
                    case 'geolocationLookup': {
                        const ip = this.getNodeParameter('geolocationIp', i) || '';
                        const userAgent = this.getNodeParameter('geolocationUserAgent', i) || '';
                        try {
                            const initialContext = {
                                itemIndex: i,
                                ip: ip.trim(),
                                userAgent: userAgent.trim(),
                            };
                            const context = await runPipeline(this, initialContext, [
                                validateGeolocationLookupAction,
                                buildGeolocationLookupPayloadAction,
                                executeGeolocationLookupRequestAction,
                            ]);
                            responseData = {
                                operation: 'geolocationLookup',
                                success: true,
                                ip: context.ip,
                                userAgent: context.userAgent || undefined,
                                apiResponse: context.response,
                                location: ((_f = context.response) === null || _f === void 0 ? void 0 : _f.location) || ((_g = context.response) === null || _g === void 0 ? void 0 : _g.data),
                                message: 'Geolocation lookup completed successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'geolocationLookup', { itemIndex: i });
                            responseData = {
                                operation: 'geolocationLookup',
                                success: false,
                                ip: ip ? '[REDACTED]' : undefined,
                                error: createSecureErrorMessage(error, 'geolocationLookup'),
                                message: 'Failed to look up geolocation. Please verify the IP address and try again.',
                            };
                        }
                        break;
                    }
                    case 'listFields': {
                        try {
                            const response = await makeBentoRequest.call(this, 'GET', '/api/v1/fetch/fields', undefined, i);
                            const fields = Array.isArray(response === null || response === void 0 ? void 0 : response.data)
                                ? response.data
                                : Array.isArray(response)
                                    ? response
                                    : [];
                            responseData = {
                                operation: 'listFields',
                                success: true,
                                total: fields.length,
                                fields,
                                apiResponse: response,
                                message: `Retrieved ${fields.length} fields`,
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'listFields', { itemIndex: i });
                            responseData = {
                                operation: 'listFields',
                                success: false,
                                error: createSecureErrorMessage(error, 'listFields'),
                                message: 'Failed to list fields. Check your credentials and try again.',
                            };
                        }
                        break;
                    }
                    case 'listBroadcasts': {
                        const status = this.getNodeParameter('listBroadcastsStatus', i);
                        const createdAfter = this.getNodeParameter('listBroadcastsCreatedAfter', i);
                        const tagCollection = this.getNodeParameter('listBroadcastsTagIds', i);
                        try {
                            const initialContext = {
                                itemIndex: i,
                                status,
                                rawCreatedAfter: createdAfter,
                                tagIds: ((_h = tagCollection === null || tagCollection === void 0 ? void 0 : tagCollection.tagId) !== null && _h !== void 0 ? _h : [])
                                    .map(tag => { var _a; return (_a = tag === null || tag === void 0 ? void 0 : tag.id) === null || _a === void 0 ? void 0 : _a.trim(); })
                                    .filter((id) => !!id),
                            };
                            const context = await runPipeline(this, initialContext, [
                                validateListBroadcastsAction,
                                buildListBroadcastsEndpointAction,
                                executeListBroadcastsRequestAction,
                            ]);
                            const broadcasts = Array.isArray((_j = context.response) === null || _j === void 0 ? void 0 : _j.broadcasts)
                                ? context.response.broadcasts
                                : Array.isArray(context.response)
                                    ? context.response
                                    : [];
                            const scheduledCount = broadcasts.filter((broadcast) => (broadcast === null || broadcast === void 0 ? void 0 : broadcast.status) === 'scheduled').length;
                            responseData = {
                                operation: 'listBroadcasts',
                                success: true,
                                filters: {
                                    status: context.status !== 'any' ? context.status : undefined,
                                    createdAfter: context.createdAfter,
                                    tagIds: context.tagIds.length > 0 ? context.tagIds : undefined,
                                },
                                total: broadcasts.length,
                                scheduledCount,
                                apiResponse: context.response,
                                message: `Retrieved ${broadcasts.length} broadcasts`,
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'listBroadcasts', { itemIndex: i });
                            responseData = {
                                operation: 'listBroadcasts',
                                success: false,
                                error: createSecureErrorMessage(error, 'listBroadcasts'),
                                message: 'Failed to list broadcasts. Review filters and try again.',
                            };
                        }
                        break;
                    }
                    case 'listSequences': {
                        const page = validatePositiveIntegerInput.call(this, this.getNodeParameter('listSequencesPage', i), 'Page', i);
                        try {
                            const response = await makeBentoRequest.call(this, 'GET', page > 1
                                ? `/api/v1/fetch/sequences?page=${page}`
                                : '/api/v1/fetch/sequences', undefined, i);
                            const sequences = Array.isArray(response === null || response === void 0 ? void 0 : response.data)
                                ? response.data
                                : Array.isArray(response)
                                    ? response
                                    : [];
                            responseData = {
                                operation: 'listSequences',
                                success: true,
                                page,
                                total: sequences.length,
                                sequences,
                                apiResponse: response,
                                message: `Retrieved ${sequences.length} sequences`,
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'listSequences', { itemIndex: i });
                            responseData = {
                                operation: 'listSequences',
                                success: false,
                                page,
                                error: createSecureErrorMessage(error, 'listSequences'),
                                message: 'Failed to list sequences. Check your credentials and try again.',
                            };
                        }
                        break;
                    }
                    case 'listTags': {
                        try {
                            const response = await makeBentoRequest.call(this, 'GET', '/api/v1/fetch/tags', undefined, i);
                            const tags = Array.isArray(response === null || response === void 0 ? void 0 : response.data)
                                ? response.data
                                : Array.isArray(response)
                                    ? response
                                    : [];
                            responseData = {
                                operation: 'listTags',
                                success: true,
                                total: tags.length,
                                tags,
                                apiResponse: response,
                                message: `Retrieved ${tags.length} tags`,
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'listTags', { itemIndex: i });
                            responseData = {
                                operation: 'listTags',
                                success: false,
                                error: createSecureErrorMessage(error, 'listTags'),
                                message: 'Failed to list tags. Check your credentials and try again.',
                            };
                        }
                        break;
                    }
                    case 'listWorkflows': {
                        const page = validatePositiveIntegerInput.call(this, this.getNodeParameter('listWorkflowsPage', i), 'Page', i);
                        try {
                            const response = await makeBentoRequest.call(this, 'GET', page > 1
                                ? `/api/v1/fetch/workflows?page=${page}`
                                : '/api/v1/fetch/workflows', undefined, i);
                            const workflows = Array.isArray(response === null || response === void 0 ? void 0 : response.data)
                                ? response.data
                                : Array.isArray(response)
                                    ? response
                                    : [];
                            responseData = {
                                operation: 'listWorkflows',
                                success: true,
                                page,
                                total: workflows.length,
                                workflows,
                                apiResponse: response,
                                message: `Retrieved ${workflows.length} workflows`,
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'listWorkflows', { itemIndex: i });
                            responseData = {
                                operation: 'listWorkflows',
                                success: false,
                                page,
                                error: createSecureErrorMessage(error, 'listWorkflows'),
                                message: 'Failed to list workflows. Check your credentials and try again.',
                            };
                        }
                        break;
                    }
                    case 'reportStats': {
                        const reportId = this.getNodeParameter('reportStatsReportId', i);
                        try {
                            const initialContext = {
                                itemIndex: i,
                                reportId: reportId.trim(),
                            };
                            const context = await runPipeline(this, initialContext, [
                                validateReportStatsAction,
                                buildReportStatsEndpointAction,
                                executeReportStatsRequestAction,
                            ]);
                            const reportData = ((_k = context.response) === null || _k === void 0 ? void 0 : _k.report) || ((_l = context.response) === null || _l === void 0 ? void 0 : _l.data) || context.response;
                            const metricsSource = [reportData === null || reportData === void 0 ? void 0 : reportData.metrics, reportData];
                            const summaryMetrics = {};
                            const totalSends = findNumericMetric(metricsSource, ['total_sends', 'sends']);
                            if (typeof totalSends === 'number')
                                summaryMetrics.totalSends = totalSends;
                            const opens = findNumericMetric(metricsSource, ['opens', 'open_count', 'total_opens']);
                            if (typeof opens === 'number')
                                summaryMetrics.opens = opens;
                            const clicks = findNumericMetric(metricsSource, ['clicks', 'click_count', 'total_clicks']);
                            if (typeof clicks === 'number')
                                summaryMetrics.clicks = clicks;
                            const revenue = findNumericMetric(metricsSource, ['revenue', 'total_revenue', 'gross_revenue']);
                            if (typeof revenue === 'number')
                                summaryMetrics.revenue = revenue;
                            const conversions = findNumericMetric(metricsSource, ['conversions', 'conversion_count']);
                            if (typeof conversions === 'number')
                                summaryMetrics.conversions = conversions;
                            const summary = Object.keys(summaryMetrics).length > 0
                                ? {
                                    reportId: context.reportId,
                                    metrics: summaryMetrics,
                                }
                                : undefined;
                            responseData = {
                                operation: 'reportStats',
                                success: true,
                                reportId: context.reportId,
                                apiResponse: context.response,
                                summary,
                                message: 'Report metrics retrieved successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'reportStats', { itemIndex: i });
                            responseData = {
                                operation: 'reportStats',
                                success: false,
                                reportId: reportId || undefined,
                                error: createSecureErrorMessage(error, 'reportStats'),
                                message: 'Failed to fetch report metrics. Verify the report ID and try again.',
                            };
                        }
                        break;
                    }
                    case 'sendBroadcast': {
                        const name = this.getNodeParameter('sendBroadcastName', i) || '';
                        const subject = this.getNodeParameter('sendBroadcastSubject', i) || '';
                        const content = this.getNodeParameter('sendBroadcastContent', i) || '';
                        const type = this.getNodeParameter('sendBroadcastType', i);
                        const fromEmail = this.getNodeParameter('sendBroadcastFromEmail', i) || '';
                        const fromName = this.getNodeParameter('sendBroadcastFromName', i) || '';
                        const approved = this.getNodeParameter('sendBroadcastApproved', i);
                        const inclusiveTags = this.getNodeParameter('sendBroadcastInclusiveTags', i) || '';
                        const exclusiveTags = this.getNodeParameter('sendBroadcastExclusiveTags', i) || '';
                        const segmentId = this.getNodeParameter('sendBroadcastSegmentId', i) || '';
                        const batchSizePerHour = this.getNodeParameter('sendBroadcastBatchSizePerHour', i);
                        const confirm = this.getNodeParameter('sendBroadcastConfirm', i);
                        try {
                            const initialContext = {
                                itemIndex: i,
                                name: name.trim(),
                                subject: subject.trim(),
                                content,
                                type,
                                fromEmail: fromEmail.trim(),
                                fromName: fromName.trim(),
                                approved,
                                inclusiveTags: inclusiveTags.trim() || undefined,
                                exclusiveTags: exclusiveTags.trim() || undefined,
                                segmentId: segmentId.trim() || undefined,
                                batchSizePerHour: Number.isFinite(batchSizePerHour) && batchSizePerHour > 0
                                    ? batchSizePerHour
                                    : undefined,
                                confirmed: confirm,
                            };
                            const context = await runPipeline(this, initialContext, [
                                validateSendBroadcastAction,
                                buildSendBroadcastPayloadAction,
                                executeSendBroadcastRequestAction,
                            ]);
                            const errors = Array.isArray((_m = context.response) === null || _m === void 0 ? void 0 : _m.errors) ? context.response.errors : undefined;
                            const broadcasts = Array.isArray((_o = context.response) === null || _o === void 0 ? void 0 : _o.broadcasts)
                                ? context.response.broadcasts
                                : undefined;
                            responseData = {
                                operation: 'sendBroadcast',
                                success: !errors || errors.length === 0,
                                name: context.name,
                                subject: context.subject,
                                approved: context.approved,
                                segmentId: context.segmentId,
                                apiResponse: context.response,
                                createdBroadcasts: broadcasts,
                                errors: errors && errors.length > 0 ? errors : undefined,
                                message: errors && errors.length > 0
                                    ? 'Broadcast batch submitted with partial errors. Review the errors array for details.'
                                    : 'Broadcast batch submitted successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'sendBroadcast', { itemIndex: i });
                            responseData = {
                                operation: 'sendBroadcast',
                                success: false,
                                name: name || undefined,
                                error: createSecureErrorMessage(error, 'sendBroadcast'),
                                message: 'Failed to submit broadcast batch. Verify the campaign details and try again.',
                            };
                        }
                        break;
                    }
                    case 'segmentStats': {
                        const segmentId = this.getNodeParameter('segmentStatsSegmentId', i) || '';
                        try {
                            const initialContext = {
                                itemIndex: i,
                                segmentId: segmentId.trim(),
                            };
                            const context = await runPipeline(this, initialContext, [
                                validateSegmentStatsAction,
                                buildSegmentStatsEndpointAction,
                                executeSegmentStatsRequestAction,
                            ]);
                            const metrics = ((_p = context.response) === null || _p === void 0 ? void 0 : _p.metrics) || ((_r = (_q = context.response) === null || _q === void 0 ? void 0 : _q.data) === null || _r === void 0 ? void 0 : _r.metrics) || context.response;
                            const summaryMetrics = {};
                            const subscriberCount = (_t = (_s = metrics === null || metrics === void 0 ? void 0 : metrics.total_subscribers) !== null && _s !== void 0 ? _s : metrics === null || metrics === void 0 ? void 0 : metrics.totalSubscribers) !== null && _t !== void 0 ? _t : metrics === null || metrics === void 0 ? void 0 : metrics.subscriber_count;
                            if (typeof subscriberCount === 'number')
                                summaryMetrics.totalSubscribers = subscriberCount;
                            const opens = (_v = (_u = metrics === null || metrics === void 0 ? void 0 : metrics.opens) !== null && _u !== void 0 ? _u : metrics === null || metrics === void 0 ? void 0 : metrics.open_count) !== null && _v !== void 0 ? _v : metrics === null || metrics === void 0 ? void 0 : metrics.total_opens;
                            if (typeof opens === 'number')
                                summaryMetrics.opens = opens;
                            const clicks = (_x = (_w = metrics === null || metrics === void 0 ? void 0 : metrics.clicks) !== null && _w !== void 0 ? _w : metrics === null || metrics === void 0 ? void 0 : metrics.click_count) !== null && _x !== void 0 ? _x : metrics === null || metrics === void 0 ? void 0 : metrics.total_clicks;
                            if (typeof clicks === 'number')
                                summaryMetrics.clicks = clicks;
                            const unsubscribes = (_z = (_y = metrics === null || metrics === void 0 ? void 0 : metrics.unsubscribes) !== null && _y !== void 0 ? _y : metrics === null || metrics === void 0 ? void 0 : metrics.unsubscribe_count) !== null && _z !== void 0 ? _z : metrics === null || metrics === void 0 ? void 0 : metrics.total_unsubscribes;
                            if (typeof unsubscribes === 'number')
                                summaryMetrics.unsubscribes = unsubscribes;
                            const summary = Object.keys(summaryMetrics).length > 0
                                ? {
                                    segmentId: context.segmentId,
                                    metrics: summaryMetrics,
                                }
                                : undefined;
                            responseData = {
                                operation: 'segmentStats',
                                success: true,
                                segmentId: context.segmentId,
                                apiResponse: context.response,
                                summary,
                                message: 'Segment metrics retrieved successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'segmentStats', { itemIndex: i });
                            responseData = {
                                operation: 'segmentStats',
                                success: false,
                                segmentId: segmentId || undefined,
                                error: createSecureErrorMessage(error, 'segmentStats'),
                                message: 'Failed to fetch segment metrics. Verify the segment ID and try again.',
                            };
                        }
                        break;
                    }
                    case 'siteStats': {
                        try {
                            const initialContext = {
                                itemIndex: i,
                            };
                            const context = await runPipeline(this, initialContext, [
                                buildSiteStatsEndpointAction,
                                executeSiteStatsRequestAction,
                            ]);
                            const totals = ((_0 = context.response) === null || _0 === void 0 ? void 0 : _0.totals) || ((_2 = (_1 = context.response) === null || _1 === void 0 ? void 0 : _1.data) === null || _2 === void 0 ? void 0 : _2.totals) || context.response;
                            const summaryTotals = {};
                            const totalSubscribers = (_3 = totals === null || totals === void 0 ? void 0 : totals.total_subscribers) !== null && _3 !== void 0 ? _3 : totals === null || totals === void 0 ? void 0 : totals.totalSubscribers;
                            if (typeof totalSubscribers === 'number')
                                summaryTotals.totalSubscribers = totalSubscribers;
                            const activeSubscribers = (_4 = totals === null || totals === void 0 ? void 0 : totals.active_subscribers) !== null && _4 !== void 0 ? _4 : totals === null || totals === void 0 ? void 0 : totals.activeSubscribers;
                            if (typeof activeSubscribers === 'number')
                                summaryTotals.activeSubscribers = activeSubscribers;
                            const inactiveSubscribers = (_5 = totals === null || totals === void 0 ? void 0 : totals.inactive_subscribers) !== null && _5 !== void 0 ? _5 : totals === null || totals === void 0 ? void 0 : totals.inactiveSubscribers;
                            if (typeof inactiveSubscribers === 'number')
                                summaryTotals.inactiveSubscribers = inactiveSubscribers;
                            const summary = Object.keys(summaryTotals).length > 0
                                ? {
                                    totals: summaryTotals,
                                }
                                : undefined;
                            responseData = {
                                operation: 'siteStats',
                                success: true,
                                apiResponse: context.response,
                                summary,
                                message: 'Site metrics retrieved successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'siteStats', { itemIndex: i });
                            responseData = {
                                operation: 'siteStats',
                                success: false,
                                error: createSecureErrorMessage(error, 'siteStats'),
                                message: 'Failed to fetch site metrics. Try again later.',
                            };
                        }
                        break;
                    }
                    default:
                        throw new n8n_workflow_1.NodeOperationError(this.getNode(), `Unknown operation: ${operation}`, {
                            itemIndex: i,
                        });
                }
                returnData.push({
                    json: responseData,
                    pairedItem: { item: i },
                });
            }
            catch (error) {
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
exports.Bento = Bento;
async function runPipeline(executor, initialContext, actions) {
    let context = initialContext;
    for (const action of actions) {
        context = await action.call(executor, context);
    }
    return context;
}
function validateContentModerationAction(context) {
    const { content, itemIndex } = context;
    if (typeof content !== 'string' || content.trim() === '') {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Content is required for moderation', {
            itemIndex,
        });
    }
    validateInputLength.call(this, content, INPUT_LIMITS.TEXT_CONTENT, 'Content', itemIndex);
    return context;
}
function buildContentModerationPayloadAction(context) {
    const trimmedContent = context.content.trim();
    context.content = trimmedContent;
    const metadata = {};
    for (const pair of context.metadataPairs) {
        if ((pair === null || pair === void 0 ? void 0 : pair.key) && (pair === null || pair === void 0 ? void 0 : pair.value)) {
            validateInputLength.call(this, pair.key, INPUT_LIMITS.CUSTOM_FIELD_KEY, 'Metadata Key', context.itemIndex);
            validateInputLength.call(this, pair.value, INPUT_LIMITS.CUSTOM_FIELD_VALUE, 'Metadata Value', context.itemIndex);
            metadata[pair.key] = pair.value;
        }
    }
    context.metadata = metadata;
    const payload = {
        content: trimmedContent,
    };
    if (Object.keys(metadata).length > 0) {
        payload.metadata = metadata;
    }
    context.payload = payload;
    return context;
}
async function executeContentModerationRequestAction(context) {
    if (!context.payload) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Failed to build request payload for content moderation', {
            itemIndex: context.itemIndex,
        });
    }
    if (!validatePayloadSize(context.payload)) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Content moderation payload exceeds size limit', {
            itemIndex: context.itemIndex,
        });
    }
    context.response = await makeBentoRequest.call(this, 'POST', '/api/v1/experimental/content_moderation', context.payload, context.itemIndex);
    return context;
}
function validateGenderGuessAction(context) {
    const { email, firstName, lastName, fullName, itemIndex } = context;
    if (!fullName) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Provide at least a first or last name for gender guess', {
            itemIndex,
        });
    }
    validateInputLength.call(this, fullName, INPUT_LIMITS.VALIDATE_NAME, 'Name', itemIndex);
    if (firstName) {
        validateInputLength.call(this, firstName, INPUT_LIMITS.NAME, 'First Name', itemIndex);
    }
    if (lastName) {
        validateInputLength.call(this, lastName, INPUT_LIMITS.NAME, 'Last Name', itemIndex);
    }
    if (email) {
        validateInputLength.call(this, email, INPUT_LIMITS.EMAIL, 'Email', itemIndex);
        if (!isValidEmail(email)) {
            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid email format', {
                itemIndex,
            });
        }
    }
    return context;
}
function buildGenderGuessPayloadAction(context) {
    var _a, _b;
    const payload = {};
    const emailForRequest = (_a = context.requestEmail) !== null && _a !== void 0 ? _a : context.email;
    if (emailForRequest) {
        payload.email = emailForRequest;
        context.email = emailForRequest;
        context.requestEmail = emailForRequest;
    }
    const fullName = (_b = context.fullName) !== null && _b !== void 0 ? _b : [context.firstName, context.lastName].filter(Boolean).join(' ').trim();
    if (fullName) {
        payload.name = fullName;
        context.fullName = fullName;
    }
    const queryParams = [];
    if (fullName) {
        queryParams.push(`name=${encodeURIComponent(fullName)}`);
    }
    if (context.requestEmail) {
        queryParams.push(`email=${encodeURIComponent(context.requestEmail)}`);
    }
    context.endpoint = `/api/v1/experimental/gender${queryParams.length ? `?${queryParams.join('&')}` : ''}`;
    if (context.firstName) {
        payload.first_name = context.firstName;
    }
    if (context.lastName) {
        payload.last_name = context.lastName;
    }
    if (!payload.name) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Unable to build payload for gender guess', {
            itemIndex: context.itemIndex,
        });
    }
    context.payload = payload;
    return context;
}
async function executeGenderGuessRequestAction(context) {
    var _a;
    if (!context.payload) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Missing payload for gender guess', {
            itemIndex: context.itemIndex,
        });
    }
    if (!validatePayloadSize(context.payload)) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Gender guess payload exceeds size limit', {
            itemIndex: context.itemIndex,
        });
    }
    const endpoint = (_a = context.endpoint) !== null && _a !== void 0 ? _a : '/api/v1/experimental/gender';
    context.response = await makeBentoRequest.call(this, 'POST', endpoint, context.payload, context.itemIndex);
    return context;
}
function validateGeolocationLookupAction(context) {
    const { ip, userAgent, itemIndex } = context;
    if (!ip) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'IP address is required for geolocation lookup', {
            itemIndex,
        });
    }
    validateInputLength.call(this, ip, INPUT_LIMITS.IP_ADDRESS, 'IP Address', itemIndex);
    if (userAgent) {
        validateInputLength.call(this, userAgent, INPUT_LIMITS.USER_AGENT, 'User Agent', itemIndex);
    }
    return context;
}
function buildGeolocationLookupPayloadAction(context) {
    const queryParams = [`ip=${encodeURIComponent(context.ip)}`];
    if (context.userAgent) {
        queryParams.push(`user_agent=${encodeURIComponent(context.userAgent)}`);
    }
    context.endpoint = `/api/v1/experimental/geolocation?${queryParams.join('&')}`;
    context.payload = undefined;
    return context;
}
async function executeGeolocationLookupRequestAction(context) {
    var _a;
    const endpoint = (_a = context.endpoint) !== null && _a !== void 0 ? _a : `/api/v1/experimental/geolocation?ip=${encodeURIComponent(context.ip)}`;
    context.response = await makeBentoRequest.call(this, 'GET', endpoint, undefined, context.itemIndex);
    return context;
}
function formatDateToYmd(date) {
    const year = date.getUTCFullYear();
    const month = String(date.getUTCMonth() + 1).padStart(2, '0');
    const day = String(date.getUTCDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
}
function parseDateInput(executor, value, fieldName, itemIndex) {
    if (!value) {
        throw new n8n_workflow_1.NodeOperationError(executor.getNode(), `${fieldName} is required when using a custom range`, {
            itemIndex,
        });
    }
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        throw new n8n_workflow_1.NodeOperationError(executor.getNode(), `${fieldName} is invalid`, {
            itemIndex,
        });
    }
    return parsed;
}
function buildSiteStatsEndpointAction(context) {
    context.endpoint = '/api/v1/stats/site';
    return context;
}
async function executeSiteStatsRequestAction(context) {
    if (!context.endpoint) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Site metrics endpoint not generated', {
            itemIndex: context.itemIndex,
        });
    }
    context.response = await makeBentoRequest.call(this, 'GET', context.endpoint, undefined, context.itemIndex);
    return context;
}
function validateSegmentStatsAction(context) {
    var _a;
    const segmentId = (_a = context.segmentId) === null || _a === void 0 ? void 0 : _a.trim();
    if (!segmentId) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Segment ID is required for segment metrics', {
            itemIndex: context.itemIndex,
        });
    }
    validateInputLength.call(this, segmentId, INPUT_LIMITS.SEGMENT_ID, 'Segment ID', context.itemIndex);
    context.segmentId = segmentId;
    return context;
}
function buildSegmentStatsEndpointAction(context) {
    context.endpoint = `/api/v1/stats/segment?segment_id=${encodeURIComponent(context.segmentId)}`;
    return context;
}
async function executeSegmentStatsRequestAction(context) {
    if (!context.endpoint) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Segment metrics endpoint not generated', {
            itemIndex: context.itemIndex,
        });
    }
    context.response = await makeBentoRequest.call(this, 'GET', context.endpoint, undefined, context.itemIndex);
    return context;
}
function validateReportStatsAction(context) {
    if (!context.reportId) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Report ID is required', {
            itemIndex: context.itemIndex,
        });
    }
    validateInputLength.call(this, context.reportId, INPUT_LIMITS.SEGMENT_ID, 'Report ID', context.itemIndex);
    return context;
}
function buildReportStatsEndpointAction(context) {
    context.endpoint = `/api/v1/stats/report?report_id=${encodeURIComponent(context.reportId)}`;
    return context;
}
async function executeReportStatsRequestAction(context) {
    if (!context.endpoint) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Report metrics endpoint not generated', {
            itemIndex: context.itemIndex,
        });
    }
    context.response = await makeBentoRequest.call(this, 'GET', context.endpoint, undefined, context.itemIndex);
    return context;
}
function findNumericMetric(sources, keys) {
    for (const source of sources) {
        if (!source || typeof source !== 'object') {
            continue;
        }
        for (const key of keys) {
            const value = source[key];
            if (typeof value === 'number' && Number.isFinite(value)) {
                return value;
            }
        }
    }
    return undefined;
}
function validateListBroadcastsAction(context) {
    if (context.rawCreatedAfter) {
        const parsed = parseDateInput(this, context.rawCreatedAfter, 'Created After', context.itemIndex);
        context.createdAfter = formatDateToYmd(parsed);
    }
    if (context.tagIds.length > 0) {
        context.tagIds = context.tagIds.map(tagId => {
            validateInputLength.call(this, tagId, INPUT_LIMITS.SEGMENT_ID, 'Tag ID', context.itemIndex);
            return tagId;
        });
    }
    return context;
}
function buildListBroadcastsEndpointAction(context) {
    const params = new URLSearchParams();
    if (context.status && context.status !== 'any') {
        params.append('status', context.status);
    }
    if (context.createdAfter) {
        params.append('created_after', context.createdAfter);
    }
    if (context.tagIds.length > 0) {
        params.append('tag_ids', context.tagIds.join(','));
    }
    const queryString = params.toString();
    context.endpoint = queryString
        ? `/api/v1/fetch/broadcasts?${queryString}`
        : '/api/v1/fetch/broadcasts';
    return context;
}
async function executeListBroadcastsRequestAction(context) {
    if (!context.endpoint) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Broadcast listing endpoint not generated', {
            itemIndex: context.itemIndex,
        });
    }
    context.response = await makeBentoRequest.call(this, 'GET', context.endpoint, undefined, context.itemIndex);
    return context;
}
function validateSendBroadcastAction(context) {
    if (!context.confirmed) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Please enable Confirm Send to queue the broadcast', {
            itemIndex: context.itemIndex,
        });
    }
    if (!context.name) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Campaign name is required', {
            itemIndex: context.itemIndex,
        });
    }
    validateInputLength.call(this, context.name, INPUT_LIMITS.VALIDATE_NAME, 'Campaign Name', context.itemIndex);
    if (!context.subject) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Subject is required', {
            itemIndex: context.itemIndex,
        });
    }
    validateInputLength.call(this, context.subject, INPUT_LIMITS.SUBJECT, 'Subject', context.itemIndex);
    if (!context.content || context.content.trim() === '') {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Content cannot be empty', {
            itemIndex: context.itemIndex,
        });
    }
    const contentLimit = context.type === 'html' ? INPUT_LIMITS.HTML_CONTENT : INPUT_LIMITS.TEXT_CONTENT;
    validateInputLength.call(this, context.content, contentLimit, 'Content', context.itemIndex);
    if (!context.fromEmail) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'From email is required', {
            itemIndex: context.itemIndex,
        });
    }
    validateInputLength.call(this, context.fromEmail, INPUT_LIMITS.EMAIL, 'From Email', context.itemIndex);
    if (!isValidEmail(context.fromEmail)) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'From email address is invalid', {
            itemIndex: context.itemIndex,
        });
    }
    if (!context.fromName) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'From name is required', {
            itemIndex: context.itemIndex,
        });
    }
    validateInputLength.call(this, context.fromName, INPUT_LIMITS.VALIDATE_NAME, 'From Name', context.itemIndex);
    if (!['plain', 'html'].includes(context.type)) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), `Unsupported content type: ${context.type}`, {
            itemIndex: context.itemIndex,
        });
    }
    if (context.inclusiveTags) {
        validateInputLength.call(this, context.inclusiveTags, INPUT_LIMITS.CUSTOM_FIELD_VALUE, 'Inclusive Tags', context.itemIndex);
    }
    if (context.exclusiveTags) {
        validateInputLength.call(this, context.exclusiveTags, INPUT_LIMITS.CUSTOM_FIELD_VALUE, 'Exclusive Tags', context.itemIndex);
    }
    if (context.segmentId) {
        validateInputLength.call(this, context.segmentId, INPUT_LIMITS.SEGMENT_ID, 'Segment ID', context.itemIndex);
    }
    if (context.batchSizePerHour !== undefined) {
        if (!Number.isFinite(context.batchSizePerHour) || context.batchSizePerHour <= 0) {
            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Batch size per hour must be a positive number', {
                itemIndex: context.itemIndex,
            });
        }
        context.batchSizePerHour = Math.floor(context.batchSizePerHour);
    }
    return context;
}
function buildSendBroadcastPayloadAction(context) {
    const broadcastPayload = {
        name: context.name,
        subject: context.subject,
        content: context.content,
        type: context.type,
        from: {
            email: context.fromEmail,
            name: context.fromName,
        },
        approved: context.approved,
    };
    if (context.inclusiveTags) {
        broadcastPayload.inclusive_tags = context.inclusiveTags;
    }
    if (context.exclusiveTags) {
        broadcastPayload.exclusive_tags = context.exclusiveTags;
    }
    if (context.segmentId) {
        broadcastPayload.segment_id = context.segmentId;
    }
    if (context.batchSizePerHour !== undefined) {
        broadcastPayload.batch_size_per_hour = context.batchSizePerHour;
    }
    context.payload = {
        broadcasts: [broadcastPayload],
    };
    return context;
}
async function executeSendBroadcastRequestAction(context) {
    if (!context.payload) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Broadcast payload not built', {
            itemIndex: context.itemIndex,
        });
    }
    if (!validatePayloadSize(context.payload)) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Broadcast payload exceeds size limits', {
            itemIndex: context.itemIndex,
        });
    }
    context.response = await makeBentoRequest.call(this, 'POST', '/api/v1/batch/broadcasts', context.payload, context.itemIndex);
    return context;
}
async function makeBentoRequest(method, endpoint, body, itemIndex = 0) {
    var _a;
    const nodeId = `${this.getNode().id}-${this.getInstanceId()}`;
    if (body && !validatePayloadSize(body)) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), `Request payload exceeds maximum size limit of ${REQUEST_LIMITS.MAX_PAYLOAD_SIZE / 1024 / 1024}MB`, { itemIndex });
    }
    const credentials = await this.getCredentials('bentoApi');
    if (!credentials) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'No credentials provided', {
            itemIndex,
        });
    }
    const { publishableKey, secretKey, siteUuid } = credentials;
    if (!publishableKey || typeof publishableKey !== 'string' || publishableKey.trim() === '') {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Missing or invalid publishableKey in credentials', {
            itemIndex,
        });
    }
    if (!secretKey || typeof secretKey !== 'string' || secretKey.trim() === '') {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Missing or invalid secretKey in credentials', {
            itemIndex,
        });
    }
    if (!siteUuid || typeof siteUuid !== 'string' || siteUuid.trim() === '') {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Missing or invalid siteUuid in credentials', {
            itemIndex,
        });
    }
    const pubKey = publishableKey.trim();
    const secKey = secretKey.trim();
    const uuid = siteUuid.trim();
    const authHeader = 'Basic ' + buffer_1.Buffer.from(`${pubKey}:${secKey}`).toString('base64');
    const baseUrl = 'https://app.bentonow.com';
    if (!uuid || typeof uuid !== 'string' || uuid.trim() === '') {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid site_uuid in credentials - must be a non-empty string', {
            itemIndex,
        });
    }
    const encodedUuid = encodeURIComponent(uuid.trim());
    const separator = endpoint.includes('?') ? '&' : '?';
    const fullUrl = `${baseUrl}${endpoint}${separator}site_uuid=${encodedUuid}`;
    try {
        new URL(fullUrl);
    }
    catch (urlError) {
        logSecureError.call(this, urlError, 'URL Validation', {
            itemIndex,
            endpoint
        });
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), SECURE_ERROR_MESSAGES.INVALID_REQUEST, {
            itemIndex,
        });
    }
    await acquireRequestSlot(nodeId);
    let lastError;
    try {
        for (let attempt = 0; attempt <= REQUEST_LIMITS.MAX_RETRIES; attempt++) {
            try {
                const options = {
                    method,
                    url: fullUrl,
                    headers: {
                        Authorization: authHeader,
                        'Content-Type': 'application/json',
                        Accept: 'application/json',
                        'User-Agent': 'bento-n8n-' + uuid,
                    },
                    json: true,
                    timeout: REQUEST_LIMITS.DEFAULT_TIMEOUT,
                };
                if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
                    options.body = body;
                }
                const response = await this.helpers.httpRequest(options);
                return response;
            }
            catch (error) {
                lastError = error;
                if (error.statusCode === 429) {
                    const retryAfter = (_a = error.headers) === null || _a === void 0 ? void 0 : _a['retry-after'];
                    const delay = retryAfter ? parseInt(retryAfter) * 1000 : REQUEST_LIMITS.RATE_LIMIT_DELAY;
                    if (attempt < REQUEST_LIMITS.MAX_RETRIES) {
                        await sleep(delay);
                        continue;
                    }
                }
                if (shouldRetryRequest(error, attempt)) {
                    const delay = calculateBackoffDelay(attempt);
                    await sleep(delay);
                    continue;
                }
                break;
            }
        }
        throw lastError;
    }
    catch (error) {
        logSecureError.call(this, error, 'API Request', {
            itemIndex,
            endpoint
        });
        const secureMessage = createSecureErrorMessage(error, 'API Request');
        const nodeError = new n8n_workflow_1.NodeOperationError(this.getNode(), secureMessage, {
            itemIndex,
            description: `Failed to communicate with Bento API. Status: ${error.statusCode || 'Unknown'}`,
        });
        throw nodeError;
    }
    finally {
        releaseRequestSlot(nodeId);
    }
}
//# sourceMappingURL=Bento.node.js.map