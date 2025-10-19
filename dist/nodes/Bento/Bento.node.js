"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Bento = void 0;
const n8n_workflow_1 = require("n8n-workflow");
const buffer_1 = require("buffer");
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const INPUT_LIMITS = {
    EMAIL: 254,
    NAME: 50,
    SUBJECT: 200,
    CUSTOM_FIELD_KEY: 50,
    CUSTOM_FIELD_VALUE: 500,
    EVENT_NAME: 100,
    EVENT_PROPERTY_KEY: 50,
    EVENT_PROPERTY_VALUE: 500,
    HTML_CONTENT: 50000,
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
                            name: 'Create Subscriber',
                            value: 'createSubscriber',
                            description: 'Add a new subscriber to your Bento audience with email and profile data',
                            action: 'Create a subscriber',
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
                    displayName: 'Email',
                    name: 'blacklistEmail',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['blacklistCheck'],
                        },
                    },
                    default: '',
                    placeholder: 'user@example.com',
                    description: 'Email address to evaluate against Bento\'s blacklist service',
                },
                {
                    displayName: 'First Name',
                    name: 'blacklistFirstName',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['blacklistCheck'],
                        },
                    },
                    default: '',
                    description: 'Optional first name to improve blacklist match confidence',
                },
                {
                    displayName: 'Last Name',
                    name: 'blacklistLastName',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['blacklistCheck'],
                        },
                    },
                    default: '',
                    description: 'Optional last name to improve blacklist match confidence',
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
                    description: 'Optional IP address to include in the blacklist evaluation',
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
                    displayName: 'Date Range',
                    name: 'siteStatsRange',
                    type: 'options',
                    noDataExpression: true,
                    displayOptions: {
                        show: {
                            operation: ['siteStats'],
                        },
                    },
                    options: [
                        {
                            name: 'Last 7 Days',
                            value: 'last7Days',
                        },
                        {
                            name: 'Last 30 Days',
                            value: 'last30Days',
                        },
                        {
                            name: 'Custom',
                            value: 'custom',
                        },
                    ],
                    default: 'last7Days',
                    description: 'Preset window for pulling site metrics',
                },
                {
                    displayName: 'Start Date',
                    name: 'siteStatsStartDate',
                    type: 'dateTime',
                    displayOptions: {
                        show: {
                            operation: ['siteStats'],
                            siteStatsRange: ['custom'],
                        },
                    },
                    default: '',
                    description: 'Custom range start (required when using Custom range)',
                },
                {
                    displayName: 'End Date',
                    name: 'siteStatsEndDate',
                    type: 'dateTime',
                    displayOptions: {
                        show: {
                            operation: ['siteStats'],
                            siteStatsRange: ['custom'],
                        },
                    },
                    default: '',
                    description: 'Custom range end (required when using Custom range)',
                },
                {
                    displayName: 'Include Inactive Subscribers',
                    name: 'siteStatsIncludeInactive',
                    type: 'boolean',
                    displayOptions: {
                        show: {
                            operation: ['siteStats'],
                        },
                    },
                    default: false,
                    description: 'Whether to include inactive subscribers in the metrics response',
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
                    displayName: 'Date Range',
                    name: 'segmentStatsRange',
                    type: 'options',
                    noDataExpression: true,
                    displayOptions: {
                        show: {
                            operation: ['segmentStats'],
                        },
                    },
                    options: [
                        {
                            name: 'Last 7 Days',
                            value: 'last7Days',
                        },
                        {
                            name: 'Last 30 Days',
                            value: 'last30Days',
                        },
                        {
                            name: 'Custom',
                            value: 'custom',
                        },
                    ],
                    default: 'last7Days',
                    description: 'Preset window for pulling segment metrics',
                },
                {
                    displayName: 'Start Date',
                    name: 'segmentStatsStartDate',
                    type: 'dateTime',
                    displayOptions: {
                        show: {
                            operation: ['segmentStats'],
                            segmentStatsRange: ['custom'],
                        },
                    },
                    default: '',
                    description: 'Custom range start (required when using Custom range)',
                },
                {
                    displayName: 'End Date',
                    name: 'segmentStatsEndDate',
                    type: 'dateTime',
                    displayOptions: {
                        show: {
                            operation: ['segmentStats'],
                            segmentStatsRange: ['custom'],
                        },
                    },
                    default: '',
                    description: 'Custom range end (required when using Custom range)',
                },
                {
                    displayName: 'Report Type',
                    name: 'reportStatsType',
                    type: 'options',
                    required: true,
                    noDataExpression: true,
                    displayOptions: {
                        show: {
                            operation: ['reportStats'],
                        },
                    },
                    options: [
                        {
                            name: 'Automation',
                            value: 'automation',
                        },
                        {
                            name: 'Broadcast',
                            value: 'broadcast',
                        },
                        {
                            name: 'Revenue',
                            value: 'revenue',
                        },
                    ],
                    default: 'broadcast',
                    description: 'Report type to fetch from Bento',
                },
                {
                    displayName: 'Broadcast ID',
                    name: 'reportStatsBroadcastId',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['reportStats'],
                            reportStatsType: ['broadcast'],
                        },
                    },
                    default: '',
                    placeholder: 'broadcast_12345',
                    description: 'Identifier of the broadcast to report on',
                },
                {
                    displayName: 'Automation ID',
                    name: 'reportStatsAutomationId',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['reportStats'],
                            reportStatsType: ['automation'],
                        },
                    },
                    default: '',
                    placeholder: 'automation_12345',
                    description: 'Identifier of the automation to report on',
                },
                {
                    displayName: 'Date Range',
                    name: 'reportStatsRange',
                    type: 'options',
                    noDataExpression: true,
                    displayOptions: {
                        show: {
                            operation: ['reportStats'],
                        },
                    },
                    options: [
                        {
                            name: 'Last 7 Days',
                            value: 'last7Days',
                        },
                        {
                            name: 'Last 30 Days',
                            value: 'last30Days',
                        },
                        {
                            name: 'Custom',
                            value: 'custom',
                        },
                    ],
                    default: 'last7Days',
                    description: 'Preset window for the report',
                },
                {
                    displayName: 'Start Date',
                    name: 'reportStatsStartDate',
                    type: 'dateTime',
                    displayOptions: {
                        show: {
                            operation: ['reportStats'],
                            reportStatsRange: ['custom'],
                        },
                    },
                    default: '',
                    description: 'Custom range start (required when using Custom range)',
                },
                {
                    displayName: 'End Date',
                    name: 'reportStatsEndDate',
                    type: 'dateTime',
                    displayOptions: {
                        show: {
                            operation: ['reportStats'],
                            reportStatsRange: ['custom'],
                        },
                    },
                    default: '',
                    description: 'Custom range end (required when using Custom range)',
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
                    displayName: 'Broadcast ID',
                    name: 'sendBroadcastId',
                    type: 'string',
                    required: true,
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    default: '',
                    placeholder: 'broadcast_12345',
                    description: 'Identifier of the draft broadcast to send',
                },
                {
                    displayName: 'Subject Override',
                    name: 'sendBroadcastSubject',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    default: '',
                    description: 'Optional subject line override',
                },
                {
                    displayName: 'Audience',
                    name: 'sendBroadcastAudience',
                    type: 'options',
                    noDataExpression: true,
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    options: [
                        {
                            name: 'All Subscribers',
                            value: 'all',
                        },
                        {
                            name: 'Segment',
                            value: 'segment',
                        },
                        {
                            name: 'Tag',
                            value: 'tag',
                        },
                    ],
                    default: 'all',
                    description: 'Target audience for the broadcast',
                },
                {
                    displayName: 'Segment ID',
                    name: 'sendBroadcastSegmentId',
                    type: 'string',
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                            sendBroadcastAudience: ['segment'],
                        },
                    },
                    default: '',
                    description: 'Segment identifier to target',
                },
                {
                    displayName: 'Tag IDs',
                    name: 'sendBroadcastTagIds',
                    type: 'fixedCollection',
                    typeOptions: {
                        multipleValues: true,
                    },
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                            sendBroadcastAudience: ['tag'],
                        },
                    },
                    default: {},
                    description: 'Tag identifiers to target',
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
                    displayName: 'Send Timing',
                    name: 'sendBroadcastTiming',
                    type: 'options',
                    noDataExpression: true,
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                        },
                    },
                    options: [
                        {
                            name: 'Immediate',
                            value: 'immediate',
                        },
                        {
                            name: 'Scheduled',
                            value: 'scheduled',
                        },
                    ],
                    default: 'immediate',
                    description: 'Send right away or at a scheduled time',
                },
                {
                    displayName: 'Scheduled Send Time',
                    name: 'sendBroadcastSendAt',
                    type: 'dateTime',
                    displayOptions: {
                        show: {
                            operation: ['sendBroadcast'],
                            sendBroadcastTiming: ['scheduled'],
                        },
                    },
                    default: '',
                    description: 'Date/time to schedule the broadcast',
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
        var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t, _u, _v, _w, _x, _y, _z, _0, _1, _2;
        const items = this.getInputData();
        const returnData = [];
        for (let i = 0; i < items.length; i++) {
            try {
                const operation = this.getNodeParameter('operation', i);
                let responseData;
                switch (operation) {
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
                        const email = sanitizeEmail(this.getNodeParameter('blacklistEmail', i));
                        const firstName = this.getNodeParameter('blacklistFirstName', i);
                        const lastName = this.getNodeParameter('blacklistLastName', i);
                        const ip = this.getNodeParameter('blacklistIp', i);
                        try {
                            const initialContext = {
                                itemIndex: i,
                                email,
                                firstName,
                                lastName,
                                ip,
                            };
                            const context = await runPipeline(this, initialContext, [
                                validateBlacklistInputAction,
                                buildBlacklistPayloadAction,
                                executeBlacklistRequestAction,
                            ]);
                            responseData = {
                                operation: 'blacklistCheck',
                                success: true,
                                email: context.email,
                                firstName: context.firstName || undefined,
                                lastName: context.lastName || undefined,
                                ip: context.ip || undefined,
                                apiResponse: context.response,
                                message: 'Blacklist check completed successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'blacklistCheck', { itemIndex: i });
                            responseData = {
                                operation: 'blacklistCheck',
                                success: false,
                                email: email ? '[REDACTED]' : undefined,
                                error: createSecureErrorMessage(error, 'blacklistCheck'),
                                message: 'Failed to run blacklist check. Please verify your inputs and try again.',
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
                                metadataPairs: (_a = metadataCollection === null || metadataCollection === void 0 ? void 0 : metadataCollection.metadata) !== null && _a !== void 0 ? _a : [],
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
                        const email = sanitizeEmail(this.getNodeParameter('genderGuessEmail', i));
                        const firstName = this.getNodeParameter('genderGuessFirstName', i) || '';
                        const lastName = this.getNodeParameter('genderGuessLastName', i) || '';
                        try {
                            const initialContext = {
                                itemIndex: i,
                                email,
                                firstName: firstName.trim(),
                                lastName: lastName.trim(),
                            };
                            const context = await runPipeline(this, initialContext, [
                                validateGenderGuessAction,
                                buildGenderGuessPayloadAction,
                                executeGenderGuessRequestAction,
                            ]);
                            responseData = {
                                operation: 'genderGuess',
                                success: true,
                                email: context.email || undefined,
                                firstName: context.firstName || undefined,
                                lastName: context.lastName || undefined,
                                apiResponse: context.response,
                                summary: ((_b = context.response) === null || _b === void 0 ? void 0 : _b.prediction)
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
                                email: email ? '[REDACTED]' : undefined,
                                error: createSecureErrorMessage(error, 'genderGuess'),
                                message: 'Failed to run gender guess. Provide an email or name and try again.',
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
                                location: ((_c = context.response) === null || _c === void 0 ? void 0 : _c.location) || ((_d = context.response) === null || _d === void 0 ? void 0 : _d.data),
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
                    case 'listBroadcasts': {
                        const status = this.getNodeParameter('listBroadcastsStatus', i);
                        const createdAfter = this.getNodeParameter('listBroadcastsCreatedAfter', i);
                        const tagCollection = this.getNodeParameter('listBroadcastsTagIds', i);
                        try {
                            const initialContext = {
                                itemIndex: i,
                                status,
                                rawCreatedAfter: createdAfter,
                                tagIds: ((_e = tagCollection === null || tagCollection === void 0 ? void 0 : tagCollection.tagId) !== null && _e !== void 0 ? _e : [])
                                    .map(tag => { var _a; return (_a = tag === null || tag === void 0 ? void 0 : tag.id) === null || _a === void 0 ? void 0 : _a.trim(); })
                                    .filter((id) => !!id),
                            };
                            const context = await runPipeline(this, initialContext, [
                                validateListBroadcastsAction,
                                buildListBroadcastsEndpointAction,
                                executeListBroadcastsRequestAction,
                            ]);
                            const broadcasts = Array.isArray((_f = context.response) === null || _f === void 0 ? void 0 : _f.broadcasts)
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
                    case 'reportStats': {
                        const reportType = this.getNodeParameter('reportStatsType', i);
                        const broadcastId = this.getNodeParameter('reportStatsBroadcastId', i) || '';
                        const automationId = this.getNodeParameter('reportStatsAutomationId', i) || '';
                        const range = this.getNodeParameter('reportStatsRange', i);
                        const startDate = this.getNodeParameter('reportStatsStartDate', i);
                        const endDate = this.getNodeParameter('reportStatsEndDate', i);
                        try {
                            const initialContext = {
                                itemIndex: i,
                                reportType,
                                broadcastId: broadcastId.trim(),
                                automationId: automationId.trim(),
                                range,
                                rawStartDate: startDate,
                                rawEndDate: endDate,
                            };
                            const context = await runPipeline(this, initialContext, [
                                validateReportStatsAction,
                                resolveReportStatsDatesAction,
                                buildReportStatsEndpointAction,
                                executeReportStatsRequestAction,
                            ]);
                            const reportData = ((_g = context.response) === null || _g === void 0 ? void 0 : _g.report) || ((_h = context.response) === null || _h === void 0 ? void 0 : _h.data) || context.response;
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
                                    reportType: context.reportType,
                                    broadcastId: context.broadcastId || undefined,
                                    automationId: context.automationId || undefined,
                                    timeRange: {
                                        start: context.resolvedStartDate,
                                        end: context.resolvedEndDate,
                                    },
                                    metrics: summaryMetrics,
                                }
                                : undefined;
                            responseData = {
                                operation: 'reportStats',
                                success: true,
                                reportType: context.reportType,
                                broadcastId: context.broadcastId || undefined,
                                automationId: context.automationId || undefined,
                                range: {
                                    preset: context.range,
                                    start: context.resolvedStartDate,
                                    end: context.resolvedEndDate,
                                },
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
                                reportType,
                                broadcastId: broadcastId || undefined,
                                automationId: automationId || undefined,
                                error: createSecureErrorMessage(error, 'reportStats'),
                                message: 'Failed to fetch report metrics. Confirm the report inputs and try again.',
                            };
                        }
                        break;
                    }
                    case 'sendBroadcast': {
                        const broadcastId = this.getNodeParameter('sendBroadcastId', i) || '';
                        const subject = this.getNodeParameter('sendBroadcastSubject', i) || '';
                        const audience = this.getNodeParameter('sendBroadcastAudience', i);
                        const segmentId = this.getNodeParameter('sendBroadcastSegmentId', i) || '';
                        const tagCollection = this.getNodeParameter('sendBroadcastTagIds', i);
                        const timing = this.getNodeParameter('sendBroadcastTiming', i);
                        const sendAt = this.getNodeParameter('sendBroadcastSendAt', i);
                        const confirm = this.getNodeParameter('sendBroadcastConfirm', i);
                        try {
                            const initialContext = {
                                itemIndex: i,
                                broadcastId: broadcastId.trim(),
                                subject: subject.trim(),
                                audience,
                                segmentId: segmentId.trim(),
                                tagIds: ((_j = tagCollection === null || tagCollection === void 0 ? void 0 : tagCollection.tagId) !== null && _j !== void 0 ? _j : [])
                                    .map(tag => { var _a; return (_a = tag === null || tag === void 0 ? void 0 : tag.id) === null || _a === void 0 ? void 0 : _a.trim(); })
                                    .filter((id) => !!id),
                                timing,
                                rawSendAt: sendAt,
                                confirmed: confirm,
                            };
                            const context = await runPipeline(this, initialContext, [
                                validateSendBroadcastAction,
                                buildSendBroadcastPayloadAction,
                                executeSendBroadcastRequestAction,
                            ]);
                            const errors = Array.isArray((_k = context.response) === null || _k === void 0 ? void 0 : _k.errors) ? context.response.errors : undefined;
                            responseData = {
                                operation: 'sendBroadcast',
                                success: !errors || errors.length === 0,
                                broadcastId: context.broadcastId,
                                audience: context.audience,
                                timing: context.timing,
                                sendAt: context.sendAt,
                                apiResponse: context.response,
                                errors: errors && errors.length > 0 ? errors : undefined,
                                message: errors && errors.length > 0
                                    ? 'Broadcast sent with partial errors. Review the errors array for details.'
                                    : 'Broadcast queued successfully',
                            };
                        }
                        catch (error) {
                            logSecureError.call(this, error, 'sendBroadcast', { itemIndex: i });
                            responseData = {
                                operation: 'sendBroadcast',
                                success: false,
                                broadcastId: broadcastId || undefined,
                                error: createSecureErrorMessage(error, 'sendBroadcast'),
                                message: 'Failed to send broadcast. Confirm the inputs and try again.',
                            };
                        }
                        break;
                    }
                    case 'segmentStats': {
                        const segmentId = this.getNodeParameter('segmentStatsSegmentId', i) || '';
                        const range = this.getNodeParameter('segmentStatsRange', i);
                        const startDate = this.getNodeParameter('segmentStatsStartDate', i);
                        const endDate = this.getNodeParameter('segmentStatsEndDate', i);
                        try {
                            const initialContext = {
                                itemIndex: i,
                                segmentId: segmentId.trim(),
                                range,
                                rawStartDate: startDate,
                                rawEndDate: endDate,
                            };
                            const context = await runPipeline(this, initialContext, [
                                validateSegmentStatsAction,
                                resolveSegmentStatsDatesAction,
                                buildSegmentStatsEndpointAction,
                                executeSegmentStatsRequestAction,
                            ]);
                            const metrics = ((_l = context.response) === null || _l === void 0 ? void 0 : _l.metrics) || ((_o = (_m = context.response) === null || _m === void 0 ? void 0 : _m.data) === null || _o === void 0 ? void 0 : _o.metrics) || context.response;
                            const summaryMetrics = {};
                            const subscriberCount = (_q = (_p = metrics === null || metrics === void 0 ? void 0 : metrics.total_subscribers) !== null && _p !== void 0 ? _p : metrics === null || metrics === void 0 ? void 0 : metrics.totalSubscribers) !== null && _q !== void 0 ? _q : metrics === null || metrics === void 0 ? void 0 : metrics.subscriber_count;
                            if (typeof subscriberCount === 'number')
                                summaryMetrics.totalSubscribers = subscriberCount;
                            const opens = (_s = (_r = metrics === null || metrics === void 0 ? void 0 : metrics.opens) !== null && _r !== void 0 ? _r : metrics === null || metrics === void 0 ? void 0 : metrics.open_count) !== null && _s !== void 0 ? _s : metrics === null || metrics === void 0 ? void 0 : metrics.total_opens;
                            if (typeof opens === 'number')
                                summaryMetrics.opens = opens;
                            const clicks = (_u = (_t = metrics === null || metrics === void 0 ? void 0 : metrics.clicks) !== null && _t !== void 0 ? _t : metrics === null || metrics === void 0 ? void 0 : metrics.click_count) !== null && _u !== void 0 ? _u : metrics === null || metrics === void 0 ? void 0 : metrics.total_clicks;
                            if (typeof clicks === 'number')
                                summaryMetrics.clicks = clicks;
                            const unsubscribes = (_w = (_v = metrics === null || metrics === void 0 ? void 0 : metrics.unsubscribes) !== null && _v !== void 0 ? _v : metrics === null || metrics === void 0 ? void 0 : metrics.unsubscribe_count) !== null && _w !== void 0 ? _w : metrics === null || metrics === void 0 ? void 0 : metrics.total_unsubscribes;
                            if (typeof unsubscribes === 'number')
                                summaryMetrics.unsubscribes = unsubscribes;
                            const summary = Object.keys(summaryMetrics).length > 0
                                ? {
                                    segmentId: context.segmentId,
                                    timeRange: {
                                        start: context.resolvedStartDate,
                                        end: context.resolvedEndDate,
                                    },
                                    metrics: summaryMetrics,
                                }
                                : undefined;
                            responseData = {
                                operation: 'segmentStats',
                                success: true,
                                segmentId: context.segmentId,
                                range: {
                                    preset: context.range,
                                    start: context.resolvedStartDate,
                                    end: context.resolvedEndDate,
                                },
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
                                message: 'Failed to fetch segment metrics. Verify the segment ID and date range.',
                            };
                        }
                        break;
                    }
                    case 'siteStats': {
                        const range = this.getNodeParameter('siteStatsRange', i);
                        const startDate = this.getNodeParameter('siteStatsStartDate', i);
                        const endDate = this.getNodeParameter('siteStatsEndDate', i);
                        const includeInactive = this.getNodeParameter('siteStatsIncludeInactive', i);
                        try {
                            const initialContext = {
                                itemIndex: i,
                                range,
                                rawStartDate: startDate,
                                rawEndDate: endDate,
                                includeInactive,
                            };
                            const context = await runPipeline(this, initialContext, [
                                resolveSiteStatsDatesAction,
                                buildSiteStatsEndpointAction,
                                executeSiteStatsRequestAction,
                            ]);
                            const totals = ((_x = context.response) === null || _x === void 0 ? void 0 : _x.totals) || ((_z = (_y = context.response) === null || _y === void 0 ? void 0 : _y.data) === null || _z === void 0 ? void 0 : _z.totals) || context.response;
                            const summaryTotals = {};
                            const totalSubscribers = (_0 = totals === null || totals === void 0 ? void 0 : totals.total_subscribers) !== null && _0 !== void 0 ? _0 : totals === null || totals === void 0 ? void 0 : totals.totalSubscribers;
                            if (typeof totalSubscribers === 'number')
                                summaryTotals.totalSubscribers = totalSubscribers;
                            const activeSubscribers = (_1 = totals === null || totals === void 0 ? void 0 : totals.active_subscribers) !== null && _1 !== void 0 ? _1 : totals === null || totals === void 0 ? void 0 : totals.activeSubscribers;
                            if (typeof activeSubscribers === 'number')
                                summaryTotals.activeSubscribers = activeSubscribers;
                            const inactiveSubscribers = (_2 = totals === null || totals === void 0 ? void 0 : totals.inactive_subscribers) !== null && _2 !== void 0 ? _2 : totals === null || totals === void 0 ? void 0 : totals.inactiveSubscribers;
                            if (typeof inactiveSubscribers === 'number')
                                summaryTotals.inactiveSubscribers = inactiveSubscribers;
                            const summary = Object.keys(summaryTotals).length > 0
                                ? {
                                    timeRange: {
                                        start: context.resolvedStartDate,
                                        end: context.resolvedEndDate,
                                    },
                                    includeInactive: context.includeInactive,
                                    totals: summaryTotals,
                                }
                                : undefined;
                            responseData = {
                                operation: 'siteStats',
                                success: true,
                                range: {
                                    preset: context.range,
                                    start: context.resolvedStartDate,
                                    end: context.resolvedEndDate,
                                },
                                includeInactive: context.includeInactive,
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
                                range: range,
                                error: createSecureErrorMessage(error, 'siteStats'),
                                message: 'Failed to fetch site metrics. Review date selections and try again.',
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
function validateBlacklistInputAction(context) {
    const { email, firstName, lastName, ip, itemIndex } = context;
    validateInputLength.call(this, email, INPUT_LIMITS.EMAIL, 'Email', itemIndex);
    if (!email) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Email is required for blacklist checks', {
            itemIndex,
        });
    }
    if (!isValidEmail(email)) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid email format', {
            itemIndex,
        });
    }
    if (firstName) {
        validateInputLength.call(this, firstName, INPUT_LIMITS.NAME, 'First Name', itemIndex);
    }
    if (lastName) {
        validateInputLength.call(this, lastName, INPUT_LIMITS.NAME, 'Last Name', itemIndex);
    }
    if (ip) {
        validateInputLength.call(this, ip, INPUT_LIMITS.IP_ADDRESS, 'IP Address', itemIndex);
    }
    return context;
}
function buildBlacklistPayloadAction(context) {
    const payload = {
        email: context.email,
    };
    if (context.firstName) {
        payload.first_name = context.firstName;
    }
    if (context.lastName) {
        payload.last_name = context.lastName;
    }
    if (context.ip) {
        payload.ip = context.ip;
    }
    context.payload = payload;
    return context;
}
async function executeBlacklistRequestAction(context) {
    if (!context.payload) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Failed to build request payload for blacklist check', {
            itemIndex: context.itemIndex,
        });
    }
    if (!validatePayloadSize(context.payload)) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Blacklist payload exceeds size limit', {
            itemIndex: context.itemIndex,
        });
    }
    context.response = await makeBentoRequest.call(this, 'POST', '/api/v1/experimental/blacklist_check', context.payload, context.itemIndex);
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
    const { email, firstName, lastName, itemIndex } = context;
    if (!email && !firstName && !lastName) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Provide at least an email or a first/last name for gender guess', {
            itemIndex,
        });
    }
    if (email) {
        validateInputLength.call(this, email, INPUT_LIMITS.EMAIL, 'Email', itemIndex);
        if (!isValidEmail(email)) {
            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Invalid email format', {
                itemIndex,
            });
        }
    }
    if (firstName) {
        validateInputLength.call(this, firstName, INPUT_LIMITS.NAME, 'First Name', itemIndex);
    }
    if (lastName) {
        validateInputLength.call(this, lastName, INPUT_LIMITS.NAME, 'Last Name', itemIndex);
    }
    return context;
}
function buildGenderGuessPayloadAction(context) {
    const payload = {};
    if (context.email) {
        payload.email = context.email;
    }
    if (context.firstName) {
        payload.first_name = context.firstName;
    }
    if (context.lastName) {
        payload.last_name = context.lastName;
    }
    if (Object.keys(payload).length === 0) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Unable to build payload for gender guess', {
            itemIndex: context.itemIndex,
        });
    }
    context.payload = payload;
    return context;
}
async function executeGenderGuessRequestAction(context) {
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
    context.response = await makeBentoRequest.call(this, 'POST', '/api/v1/experimental/gender_guess', context.payload, context.itemIndex);
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
    const payload = {
        ip: context.ip,
    };
    if (context.userAgent) {
        payload.user_agent = context.userAgent;
    }
    context.payload = payload;
    return context;
}
async function executeGeolocationLookupRequestAction(context) {
    if (!context.payload) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Missing payload for geolocation lookup', {
            itemIndex: context.itemIndex,
        });
    }
    if (!validatePayloadSize(context.payload)) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Geolocation payload exceeds size limit', {
            itemIndex: context.itemIndex,
        });
    }
    context.response = await makeBentoRequest.call(this, 'POST', '/api/v1/experimental/geolocation', context.payload, context.itemIndex);
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
function resolveDateRange(executor, range, rawStartDate, rawEndDate, itemIndex) {
    const now = new Date();
    switch (range) {
        case 'last7Days': {
            const endDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
            const startDate = new Date(endDate);
            startDate.setUTCDate(startDate.getUTCDate() - 6);
            return {
                start: formatDateToYmd(startDate),
                end: formatDateToYmd(endDate),
            };
        }
        case 'last30Days': {
            const endDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
            const startDate = new Date(endDate);
            startDate.setUTCDate(startDate.getUTCDate() - 29);
            return {
                start: formatDateToYmd(startDate),
                end: formatDateToYmd(endDate),
            };
        }
        case 'custom': {
            const start = parseDateInput(executor, rawStartDate, 'Start Date', itemIndex);
            const end = parseDateInput(executor, rawEndDate, 'End Date', itemIndex);
            if (start > end) {
                throw new n8n_workflow_1.NodeOperationError(executor.getNode(), 'Start Date must be before or equal to End Date', {
                    itemIndex,
                });
            }
            return {
                start: formatDateToYmd(start),
                end: formatDateToYmd(end),
            };
        }
        default:
            throw new n8n_workflow_1.NodeOperationError(executor.getNode(), `Unsupported date range preset: ${range}`, {
                itemIndex,
            });
    }
}
function resolveSiteStatsDatesAction(context) {
    const { start, end } = resolveDateRange(this, context.range, context.rawStartDate, context.rawEndDate, context.itemIndex);
    context.resolvedStartDate = start;
    context.resolvedEndDate = end;
    return context;
}
function buildSiteStatsEndpointAction(context) {
    if (!context.resolvedStartDate || !context.resolvedEndDate) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Date range could not be resolved for site metrics', {
            itemIndex: context.itemIndex,
        });
    }
    const params = new URLSearchParams();
    params.append('start_date', context.resolvedStartDate);
    params.append('end_date', context.resolvedEndDate);
    if (context.includeInactive) {
        params.append('include_inactive', 'true');
    }
    context.endpoint = `/api/v1/fetch/stats/site?${params.toString()}`;
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
function resolveSegmentStatsDatesAction(context) {
    const { start, end } = resolveDateRange(this, context.range, context.rawStartDate, context.rawEndDate, context.itemIndex);
    context.resolvedStartDate = start;
    context.resolvedEndDate = end;
    return context;
}
function buildSegmentStatsEndpointAction(context) {
    if (!context.resolvedStartDate || !context.resolvedEndDate) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Date range could not be resolved for segment metrics', {
            itemIndex: context.itemIndex,
        });
    }
    const params = new URLSearchParams();
    params.append('segment_id', context.segmentId);
    params.append('start_date', context.resolvedStartDate);
    params.append('end_date', context.resolvedEndDate);
    context.endpoint = `/api/v1/fetch/stats/segment?${params.toString()}`;
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
    if (!context.reportType) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Report type is required', {
            itemIndex: context.itemIndex,
        });
    }
    if (context.reportType === 'broadcast') {
        if (!context.broadcastId) {
            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Broadcast ID is required when report type is Broadcast', {
                itemIndex: context.itemIndex,
            });
        }
        validateInputLength.call(this, context.broadcastId, INPUT_LIMITS.SEGMENT_ID, 'Broadcast ID', context.itemIndex);
    }
    if (context.reportType === 'automation') {
        if (!context.automationId) {
            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Automation ID is required when report type is Automation', {
                itemIndex: context.itemIndex,
            });
        }
        validateInputLength.call(this, context.automationId, INPUT_LIMITS.SEGMENT_ID, 'Automation ID', context.itemIndex);
    }
    if (context.reportType === 'revenue') {
        context.broadcastId = '';
        context.automationId = '';
    }
    return context;
}
function resolveReportStatsDatesAction(context) {
    const { start, end } = resolveDateRange(this, context.range, context.rawStartDate, context.rawEndDate, context.itemIndex);
    context.resolvedStartDate = start;
    context.resolvedEndDate = end;
    return context;
}
function buildReportStatsEndpointAction(context) {
    if (!context.resolvedStartDate || !context.resolvedEndDate) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Date range could not be resolved for report metrics', {
            itemIndex: context.itemIndex,
        });
    }
    const params = new URLSearchParams();
    params.append('type', context.reportType);
    params.append('start_date', context.resolvedStartDate);
    params.append('end_date', context.resolvedEndDate);
    if (context.reportType === 'broadcast' && context.broadcastId) {
        params.append('broadcast_id', context.broadcastId);
    }
    if (context.reportType === 'automation' && context.automationId) {
        params.append('automation_id', context.automationId);
    }
    context.endpoint = `/api/v1/fetch/stats/report?${params.toString()}`;
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
    if (!context.broadcastId) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Broadcast ID is required', {
            itemIndex: context.itemIndex,
        });
    }
    validateInputLength.call(this, context.broadcastId, INPUT_LIMITS.SEGMENT_ID, 'Broadcast ID', context.itemIndex);
    if (context.subject) {
        validateInputLength.call(this, context.subject, INPUT_LIMITS.SUBJECT, 'Subject Override', context.itemIndex);
    }
    if (context.audience === 'segment') {
        if (!context.segmentId) {
            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Segment ID is required when targeting a segment', {
                itemIndex: context.itemIndex,
            });
        }
        validateInputLength.call(this, context.segmentId, INPUT_LIMITS.SEGMENT_ID, 'Segment ID', context.itemIndex);
    }
    if (context.audience === 'tag') {
        if (context.tagIds.length === 0) {
            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'At least one Tag ID is required when targeting tags', {
                itemIndex: context.itemIndex,
            });
        }
        context.tagIds = context.tagIds.map(tagId => {
            validateInputLength.call(this, tagId, INPUT_LIMITS.SEGMENT_ID, 'Tag ID', context.itemIndex);
            return tagId;
        });
    }
    if (context.timing === 'scheduled') {
        if (!context.rawSendAt) {
            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Scheduled broadcasts require a send time', {
                itemIndex: context.itemIndex,
            });
        }
        const parsedSendAt = new Date(context.rawSendAt);
        if (Number.isNaN(parsedSendAt.getTime())) {
            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Scheduled send time is invalid', {
                itemIndex: context.itemIndex,
            });
        }
        const now = new Date();
        if (parsedSendAt <= now) {
            throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Scheduled send time must be in the future', {
                itemIndex: context.itemIndex,
            });
        }
        context.sendAt = parsedSendAt.toISOString();
    }
    else if (context.rawSendAt) {
        throw new n8n_workflow_1.NodeOperationError(this.getNode(), 'Remove the scheduled send time when sending immediately', {
            itemIndex: context.itemIndex,
        });
    }
    return context;
}
function buildSendBroadcastPayloadAction(context) {
    const payload = {
        broadcast_id: context.broadcastId,
    };
    if (context.subject) {
        payload.subject = context.subject;
    }
    if (context.timing === 'scheduled' && context.sendAt) {
        payload.send_at = context.sendAt;
    }
    const filters = {};
    if (context.audience === 'segment') {
        filters.segment_ids = [context.segmentId];
    }
    if (context.audience === 'tag') {
        filters.tag_ids = context.tagIds;
    }
    if (Object.keys(filters).length > 0) {
        payload.filters = filters;
    }
    context.payload = payload;
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
                if (body && (method === 'POST' || method === 'PUT')) {
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