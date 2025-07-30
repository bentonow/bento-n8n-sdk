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
        if (pattern.test(html)) {
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
        sanitized = sanitized.replace(pattern, '');
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
                            name: 'Send Transactional Email',
                            value: 'sendTransactionalEmail',
                            description: 'Send personalized transactional emails using Bento templates',
                            action: 'Send a transactional email',
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
            ],
        };
    }
    async execute() {
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
                releaseRequestSlot(nodeId);
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