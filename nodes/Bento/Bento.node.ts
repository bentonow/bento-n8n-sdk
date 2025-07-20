import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionType, NodeOperationError } from 'n8n-workflow';
import { Buffer } from 'buffer';

// Email validation regex constant - RFC-compliant
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

// Input validation constants
const INPUT_LIMITS = {
	EMAIL: 254,           // RFC 5321 standard
	NAME: 50,             // First/last names
	SUBJECT: 200,         // Email subjects
	CUSTOM_FIELD_KEY: 50, // Custom field keys
	CUSTOM_FIELD_VALUE: 500, // Custom field values
	EVENT_NAME: 100,      // Event names
	EVENT_PROPERTY_KEY: 50,   // Event property keys
	EVENT_PROPERTY_VALUE: 500, // Event property values
	HTML_CONTENT: 50000,  // HTML email content
	TEXT_CONTENT: 50000,  // Text email content
	USER_ID: 254,         // User IDs (typically emails)
	IP_ADDRESS: 45,       // IPv6 max length
	VALIDATE_NAME: 100,   // Name for validation
} as const;

// HTML validation patterns
const DANGEROUS_HTML_PATTERNS = [
	/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,  // Script tags
	/javascript:/gi,                                        // JavaScript URLs
	/on\w+\s*=/gi,                                         // Event handlers (onclick, onload, etc.)
	/<iframe\b[^>]*>/gi,                                   // Iframe tags
	/<object\b[^>]*>/gi,                                   // Object tags
	/<embed\b[^>]*>/gi,                                    // Embed tags
	/<form\b[^>]*>/gi,                                     // Form tags
	/<input\b[^>]*>/gi,                                    // Input tags
	/<meta\b[^>]*>/gi,                                     // Meta tags
	/<link\b[^>]*>/gi,                                     // Link tags (external resources)
	/data:(?!image\/)/gi,                                  // Data URLs (except images)
	/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi,   // Style tags
] as const;

// Secure error messages that don't leak sensitive information
const SECURE_ERROR_MESSAGES = {
	AUTHENTICATION_FAILED: 'Authentication failed. Please check your Bento API credentials.',
	INVALID_REQUEST: 'Request validation failed. Please check your input parameters.',
	API_ERROR: 'Bento API request failed. Please try again or contact support.',
	NETWORK_ERROR: 'Network error occurred. Please check your connection and try again.',
	VALIDATION_ERROR: 'Input validation failed. Please check your data format.',
	RATE_LIMITED: 'Rate limit exceeded. Please wait before making more requests.',
	SERVER_ERROR: 'Server error occurred. Please try again later.',
	UNKNOWN_ERROR: 'An unexpected error occurred. Please contact support if the issue persists.',
} as const;



/**
 * Helper function to validate email format with enhanced security
 * @param email - The email address to validate
 * @returns true if the email format is valid, false otherwise
 */
function isValidEmail(email: string): boolean {
	// Check if email is a string and not empty
	if (typeof email !== 'string' || email.trim() === '') {
		return false;
	}
	
	// Trim the email
	const trimmedEmail = email.trim();
	
	// Check length (RFC 5321 standard)
	if (trimmedEmail.length > 254) {
		return false;
	}
	
	// Check for basic format using enhanced regex
	if (!EMAIL_REGEX.test(trimmedEmail)) {
		return false;
	}
	
	// Additional security checks
	// Prevent emails with consecutive dots
	if (trimmedEmail.includes('..')) {
		return false;
	}
	
	// Prevent emails starting or ending with dots
	if (trimmedEmail.startsWith('.') || trimmedEmail.endsWith('.')) {
		return false;
	}
	
	// Split and validate local and domain parts
	const [localPart, domainPart] = trimmedEmail.split('@');
	
	// Local part validation (before @)
	if (localPart.length > 64) { // RFC 5321 limit
		return false;
	}
	
	// Domain part validation (after @)
	if (domainPart.length > 253) { // RFC 5321 limit
		return false;
	}
	
	// Check for valid domain structure
	const domainParts = domainPart.split('.');
	if (domainParts.length < 2) {
		return false;
	}
	
	// Each domain part should be valid
	for (const part of domainParts) {
		if (part.length === 0 || part.length > 63) {
			return false;
		}
		// Domain parts should not start or end with hyphens
		if (part.startsWith('-') || part.endsWith('-')) {
			return false;
		}
	}
	
	return true;
}

/**
 * Sanitizes email input by trimming and converting to lowercase
 * @param email - The email address to sanitize
 * @returns sanitized email string
 */
function sanitizeEmail(email: string): string {
	if (typeof email !== 'string') {
		return '';
	}
	return email.trim().toLowerCase();
}

/**
 * Validates HTML content for security issues
 * @param html - The HTML content to validate
 * @returns true if HTML is safe, false otherwise
 */
function validateHtmlContent(html: string): boolean {
	if (typeof html !== 'string') {
		return false;
	}
	
	// Check for dangerous patterns
	for (const pattern of DANGEROUS_HTML_PATTERNS) {
		if (pattern.test(html)) {
			return false;
		}
	}
	
	return true;
}

/**
 * Sanitizes HTML content by removing dangerous elements
 * @param html - The HTML content to sanitize
 * @returns sanitized HTML string
 */
function sanitizeHtmlContent(html: string): string {
	if (typeof html !== 'string') {
		return '';
	}
	
	let sanitized = html.trim();
	
	// Remove dangerous patterns
	for (const pattern of DANGEROUS_HTML_PATTERNS) {
		sanitized = sanitized.replace(pattern, '');
	}
	
	// Remove any remaining script content that might have been obfuscated
	sanitized = sanitized.replace(/javascript\s*:/gi, '');
	sanitized = sanitized.replace(/vbscript\s*:/gi, '');
	sanitized = sanitized.replace(/data\s*:/gi, '');
	
	return sanitized;
}

/**
 * Validates HTML structure and provides detailed feedback
 * @param html - The HTML content to validate
 * @returns object with validation result and details
 */
function validateHtmlStructure(html: string): { isValid: boolean; issues: string[] } {
	const issues: string[] = [];
	
	if (typeof html !== 'string') {
		issues.push('HTML content must be a string');
		return { isValid: false, issues };
	}
	
	// Check for dangerous patterns and collect specific issues
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
	
	// Check for unclosed tags (basic validation)
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

/**
 * Validates input length and throws appropriate error
 * @param input - The input string to validate
 * @param maxLength - Maximum allowed length
 * @param fieldName - Name of the field for error messages
 * @param itemIndex - Current item index for error context
 */
function validateInputLength(
	this: IExecuteFunctions,
	input: string,
	maxLength: number,
	fieldName: string,
	itemIndex: number
): void {
	if (typeof input === 'string' && input.length > maxLength) {
		throw new NodeOperationError(
			this.getNode(),
			`${fieldName} exceeds maximum length of ${maxLength} characters (current: ${input.length})`,
			{ itemIndex }
		);
	}
}

/**
 * Creates a secure error message that doesn't leak sensitive information
 * @param error - The original error object
 * @param operation - The operation that failed
 * @returns A sanitized error message
 */
function createSecureErrorMessage(error: any, operation: string): string {
	// Determine the appropriate secure message based on error type
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
	
	// Handle network and other errors
	if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
		return SECURE_ERROR_MESSAGES.NETWORK_ERROR;
	}
	
	if (error.message && error.message.includes('validation')) {
		return SECURE_ERROR_MESSAGES.VALIDATION_ERROR;
	}
	
	return SECURE_ERROR_MESSAGES.UNKNOWN_ERROR;
}

/**
 * Logs error details securely for debugging without exposing sensitive data
 * @param error - The error to log
 * @param operation - The operation that failed
 * @param context - Additional context for debugging
 */
function logSecureError(
	this: IExecuteFunctions,
	error: any,
	operation: string,
	context: { itemIndex: number; endpoint?: string }
): void {
	// Log error details for debugging (without sensitive data)
	this.logger.error('Bento Node Error', {
		operation,
		itemIndex: context.itemIndex,
		endpoint: context.endpoint,
		statusCode: error.statusCode,
		errorCode: error.code,
		hasMessage: !!error.message,
		messageLength: error.message?.length || 0,
		timestamp: new Date().toISOString(),
	});
}

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
			// Send Transactional Email parameters
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
			// Subscriber Command parameters
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
			// Validate Email parameters
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

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		for (let i = 0; i < items.length; i++) {
			try {
				const operation = this.getNodeParameter('operation', i) as string;

				let responseData;

				switch (operation) {
					case 'createSubscriber': {
						const email = sanitizeEmail(this.getNodeParameter('email', i) as string);
						const firstName = this.getNodeParameter('firstName', i) as string;
						const lastName = this.getNodeParameter('lastName', i) as string;
						const customFields = this.getNodeParameter('customFields', i) as any;

						// Validate input lengths
						validateInputLength.call(this, email, INPUT_LIMITS.EMAIL, 'Email', i);
						validateInputLength.call(this, firstName, INPUT_LIMITS.NAME, 'First Name', i);
						validateInputLength.call(this, lastName, INPUT_LIMITS.NAME, 'Last Name', i);

						// Validate required inputs
						if (!email) {
							throw new NodeOperationError(this.getNode(), 'Email is required for creating a subscriber', {
								itemIndex: i,
							});
						}

						// Validate email format
						if (!isValidEmail(email)) {
							throw new NodeOperationError(this.getNode(), 'Invalid email format', {
								itemIndex: i,
							});
						}

						// Build details object with custom fields
						const details: { [key: string]: string } = {
							first_name: firstName || '',
							last_name: lastName || '',
						};

						// Add custom fields if provided
						if (customFields.field) {
							for (const field of customFields.field) {
								if (field.key && field.value) {
									validateInputLength.call(this, field.key, INPUT_LIMITS.CUSTOM_FIELD_KEY, 'Custom Field Key', i);
									validateInputLength.call(this, field.value, INPUT_LIMITS.CUSTOM_FIELD_VALUE, 'Custom Field Value', i);
									details[field.key] = field.value;
								}
							}
						}

						// Use Events API to create subscriber with additional metadata
						// This allows for richer subscriber data and triggers automation
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
							// Use Events API for subscriber creation as per BEN-57 requirements
							const response = await makeBentoRequest.call(
								this,
								'POST',
								'/api/v1/batch/events',
								requestBody,
								i
							);

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
						} catch (error) {
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
						const email = sanitizeEmail(this.getNodeParameter('email', i) as string);

						// Validate input lengths
						validateInputLength.call(this, email, INPUT_LIMITS.EMAIL, 'Email', i);

						// Validate required inputs
						if (!email) {
							throw new NodeOperationError(this.getNode(), 'Email is required for getting subscriber information', {
								itemIndex: i,
							});
						}

						// Validate email format
						if (!isValidEmail(email)) {
							throw new NodeOperationError(this.getNode(), 'Invalid email format', {
								itemIndex: i,
							});
						}

						try {
							// Use the fetch subscribers API endpoint with email parameter
							const response = await makeBentoRequest.call(
								this,
								'GET',
								`/api/v1/fetch/subscribers?email=${encodeURIComponent(email)}`,
								undefined, // No body for GET request
								i
							);

							responseData = {
								operation: 'getSubscriber',
								success: true,
								email,
								subscriber: response,
								apiResponse: response,
								message: 'Subscriber retrieved successfully',
							};
						} catch (error) {
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
						const email = sanitizeEmail(this.getNodeParameter('email', i) as string);
						const firstName = this.getNodeParameter('firstName', i) as string;
						const lastName = this.getNodeParameter('lastName', i) as string;
						const customFields = this.getNodeParameter('customFields', i) as any;

						// Validate input lengths
						validateInputLength.call(this, email, INPUT_LIMITS.EMAIL, 'Email', i);
						validateInputLength.call(this, firstName, INPUT_LIMITS.NAME, 'First Name', i);
						validateInputLength.call(this, lastName, INPUT_LIMITS.NAME, 'Last Name', i);

						// Validate required inputs
						if (!email) {
							throw new NodeOperationError(this.getNode(), 'Email is required for updating a subscriber', {
								itemIndex: i,
							});
						}

						// Validate email format
						if (!isValidEmail(email)) {
							throw new NodeOperationError(this.getNode(), 'Invalid email format', {
								itemIndex: i,
							});
						}

						// Build subscriber object with custom fields
						const subscriberData: { [key: string]: string } = {
							email: email,
							first_name: firstName || '',
							last_name: lastName || '',
						};

						// Add custom fields if provided
						if (customFields.field) {
							for (const field of customFields.field) {
								if (field.key && field.value) {
									validateInputLength.call(this, field.key, INPUT_LIMITS.CUSTOM_FIELD_KEY, 'Custom Field Key', i);
									validateInputLength.call(this, field.value, INPUT_LIMITS.CUSTOM_FIELD_VALUE, 'Custom Field Value', i);
									subscriberData[field.key] = field.value;
								}
							}
						}

						// Use Import Subscribers API for updates as per BEN-57 requirements
						const requestBody = {
							subscribers: [subscriberData]
						};

						try {
							// Use Import Subscribers API for subscriber updates
							const response = await makeBentoRequest.call(
								this,
								'POST',
								'/api/v1/batch/subscribers',
								requestBody,
								i
							);

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
						} catch (error) {
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
						const userId = this.getNodeParameter('userId', i) as string;
						const eventName = this.getNodeParameter('eventName', i) as string;
						const eventProperties = this.getNodeParameter('eventProperties', i) as any;

						// Validate input lengths
						validateInputLength.call(this, userId, INPUT_LIMITS.USER_ID, 'User ID', i);
						validateInputLength.call(this, eventName, INPUT_LIMITS.EVENT_NAME, 'Event Name', i);

						// Validate required inputs
						if (!userId || !eventName) {
							throw new NodeOperationError(this.getNode(), 'User ID and event name are required for tracking events', {
								itemIndex: i,
							});
						}

						// Build event properties object
						const properties: { [key: string]: string } = {};
						if (eventProperties.property) {
							for (const prop of eventProperties.property) {
								if (prop.key && prop.value) {
									validateInputLength.call(this, prop.key, INPUT_LIMITS.EVENT_PROPERTY_KEY, 'Event Property Key', i);
									validateInputLength.call(this, prop.value, INPUT_LIMITS.EVENT_PROPERTY_VALUE, 'Event Property Value', i);
									properties[prop.key] = prop.value;
								}
							}
						}

						// Build request body - Bento Events API expects an array of events
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
							// Use the HTTP helper to track the event
							const response = await makeBentoRequest.call(
								this,
								'POST',
								'/api/v1/batch/events',
								requestBody,
								i
							);

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
						} catch (error) {
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
						const recipientEmail = sanitizeEmail(this.getNodeParameter('recipientEmail', i) as string);
						const fromEmail = sanitizeEmail(this.getNodeParameter('fromEmail', i) as string);
						const subject = this.getNodeParameter('subject', i) as string;
						const emailType = this.getNodeParameter('emailType', i) as string;
						const transactional = this.getNodeParameter('transactional', i) as boolean;
						const personalizations = this.getNodeParameter('personalizations', i) as any;

						// Validate input lengths
						validateInputLength.call(this, recipientEmail, INPUT_LIMITS.EMAIL, 'Recipient Email', i);
						validateInputLength.call(this, fromEmail, INPUT_LIMITS.EMAIL, 'From Email', i);
						validateInputLength.call(this, subject, INPUT_LIMITS.SUBJECT, 'Subject', i);

						// Get the appropriate body based on email type
						let htmlBody = '';
						let textBody = '';
						if (emailType === 'html') {
							htmlBody = this.getNodeParameter('htmlBody', i) as string;
							
							// Validate and sanitize HTML content
							if (htmlBody) {
								const htmlValidation = validateHtmlStructure(htmlBody);
								if (!htmlValidation.isValid) {
									throw new NodeOperationError(
										this.getNode(),
										`HTML content validation failed: ${htmlValidation.issues.join(', ')}`,
										{ itemIndex: i }
									);
								}
								
								// Sanitize the HTML content
								htmlBody = sanitizeHtmlContent(htmlBody);
							}
						} else {
							textBody = this.getNodeParameter('textBody', i) as string;
						}

						// Validate email content length
						if (emailType === 'html') {
							validateInputLength.call(this, htmlBody, INPUT_LIMITS.HTML_CONTENT, 'HTML Body', i);
						} else {
							validateInputLength.call(this, textBody, INPUT_LIMITS.TEXT_CONTENT, 'Text Body', i);
						}

						// Validate required inputs
						if (!recipientEmail || !fromEmail || !subject) {
							throw new NodeOperationError(this.getNode(), 'Recipient email, from email, and subject are required for sending transactional emails', {
								itemIndex: i,
							});
						}

						// Validate email format using centralized validation
						if (!isValidEmail(recipientEmail)) {
							throw new NodeOperationError(this.getNode(), 'Invalid recipient email format', {
								itemIndex: i,
							});
						}
						if (!isValidEmail(fromEmail)) {
							throw new NodeOperationError(this.getNode(), 'Invalid from email format', {
								itemIndex: i,
							});
						}

						// Validate email body based on type
						if (emailType === 'html' && !htmlBody) {
							throw new NodeOperationError(this.getNode(), 'HTML body is required when email type is HTML', {
								itemIndex: i,
							});
						}
						if (emailType === 'text' && !textBody) {
							throw new NodeOperationError(this.getNode(), 'Text body is required when email type is Text', {
								itemIndex: i,
							});
						}
						if (!htmlBody && !textBody) {
							throw new NodeOperationError(this.getNode(), 'Either HTML body or Text body is required', {
								itemIndex: i,
							});
						}

						// Additional HTML content security validation
						if (emailType === 'html' && htmlBody) {
							if (!validateHtmlContent(htmlBody)) {
								throw new NodeOperationError(
									this.getNode(),
									'HTML content contains potentially dangerous elements and cannot be sent',
									{ itemIndex: i }
								);
							}
						}

						// Build personalizations object
						const personalizationsData: { [key: string]: string } = {};
						if (personalizations.personalization) {
							for (const item of personalizations.personalization) {
								if (item.key && item.value) {
									// Validate personalization values that might contain HTML
									if (typeof item.value === 'string' && item.value.includes('<')) {
										if (!validateHtmlContent(item.value)) {
											throw new NodeOperationError(
												this.getNode(),
												`Personalization value for "${item.key}" contains potentially dangerous HTML content`,
												{ itemIndex: i }
											);
										}
										// Sanitize HTML in personalization values
										personalizationsData[item.key] = sanitizeHtmlContent(item.value);
									} else {
										personalizationsData[item.key] = item.value;
									}
								}
							}
						}

						// Build email object
						const emailData: any = {
							to: recipientEmail,
							from: fromEmail,
							subject: subject,
							transactional: transactional,
							personalizations: personalizationsData,
						};

						// Add body based on type
						if (emailType === 'html') {
							emailData.html_body = htmlBody;
						} else {
							emailData.text_body = textBody;
						}

						// Build request body for batch emails API
						const requestBody = {
							emails: [emailData]
						};

						try {
							// Use the batch emails API endpoint
							const response = await makeBentoRequest.call(
								this,
								'POST',
								'/api/v1/batch/emails',
								requestBody,
								i
							);

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
						} catch (error) {
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
						const email = sanitizeEmail(this.getNodeParameter('commandEmail', i) as string);
						const command = this.getNodeParameter('command', i) as string;

						// Validate input lengths
						validateInputLength.call(this, email, INPUT_LIMITS.EMAIL, 'Email', i);

						// Get parameters conditionally based on command type
						let query = '';
						let fieldKey = '';
						let fieldValue = '';
						let newEmail = '';

						// Get query parameter for commands that need it
						if (['add_tag', 'add_tag_via_event', 'remove_tag', 'remove_field'].includes(command)) {
							query = this.getNodeParameter('query', i) as string;
							validateInputLength.call(this, query, INPUT_LIMITS.CUSTOM_FIELD_KEY, 'Query', i);
						}

						// Get field parameters for add_field command
						if (command === 'add_field') {
							fieldKey = this.getNodeParameter('fieldKey', i) as string;
							fieldValue = this.getNodeParameter('fieldValue', i) as string;
							validateInputLength.call(this, fieldKey, INPUT_LIMITS.CUSTOM_FIELD_KEY, 'Field Key', i);
							validateInputLength.call(this, fieldValue, INPUT_LIMITS.CUSTOM_FIELD_VALUE, 'Field Value', i);
						}

						// Get new email for change_email command
						if (command === 'change_email') {
							newEmail = sanitizeEmail(this.getNodeParameter('newEmail', i) as string);
							validateInputLength.call(this, newEmail, INPUT_LIMITS.EMAIL, 'New Email', i);
						}

						// Validate required inputs
						if (!email) {
							throw new NodeOperationError(this.getNode(), 'Email is required for subscriber commands', {
								itemIndex: i,
							});
						}

						// Validate email format
						if (!isValidEmail(email)) {
							throw new NodeOperationError(this.getNode(), 'Invalid email format', {
								itemIndex: i,
							});
						}

						// Build command object based on the selected command
						const commandObj: any = {
							command: command,
							email: email,
						};

						// Add query based on command type
						switch (command) {
							case 'add_tag':
							case 'add_tag_via_event':
							case 'remove_tag':
							case 'remove_field':
								if (!query) {
									throw new NodeOperationError(this.getNode(), `Query is required for ${command} command`, {
										itemIndex: i,
									});
								}
								commandObj.query = query;
								break;

							case 'add_field':
								if (!fieldKey || !fieldValue) {
									throw new NodeOperationError(this.getNode(), 'Field key and value are required for add_field command', {
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
									throw new NodeOperationError(this.getNode(), 'New email is required for change_email command', {
										itemIndex: i,
									});
								}
								if (!isValidEmail(newEmail)) {
									throw new NodeOperationError(this.getNode(), 'Invalid new email format', {
										itemIndex: i,
									});
								}
								commandObj.query = newEmail;
								break;

							case 'subscribe':
							case 'unsubscribe':
								// No additional query needed for these commands
								break;

							default:
								throw new NodeOperationError(this.getNode(), `Unknown command: ${command}`, {
									itemIndex: i,
								});
						}

						// Build request body for commands API
						const requestBody = {
							command: [commandObj]
						};

						try {
							// Use the fetch commands API endpoint
							const response = await makeBentoRequest.call(
								this,
								'POST',
								'/api/v1/fetch/commands',
								requestBody,
								i
							);

							responseData = {
								operation: 'subscriberCommand',
								success: true,
								command: command,
								email: email,
								query: commandObj.query,
								apiResponse: response,
								message: `Subscriber command '${command}' executed successfully`,
							};
						} catch (error) {
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
						const email = sanitizeEmail(this.getNodeParameter('validateEmail', i) as string);
						const name = this.getNodeParameter('validateName', i) as string;
						const ip = this.getNodeParameter('validateIp', i) as string;

						// Validate input lengths
						validateInputLength.call(this, email, INPUT_LIMITS.EMAIL, 'Email', i);
						if (name) validateInputLength.call(this, name, INPUT_LIMITS.VALIDATE_NAME, 'Name', i);
						if (ip) validateInputLength.call(this, ip, INPUT_LIMITS.IP_ADDRESS, 'IP Address', i);

						// Validate required inputs
						if (!email) {
							throw new NodeOperationError(this.getNode(), 'Email is required for validation', {
								itemIndex: i,
							});
						}

						// Validate email format
						if (!isValidEmail(email)) {
							throw new NodeOperationError(this.getNode(), 'Invalid email format', {
								itemIndex: i,
							});
						}

						// Build query parameters for the validation endpoint
						const queryParams = new URLSearchParams();
						queryParams.append('email', email);
						
						if (name) {
							queryParams.append('name', name);
						}
						
						if (ip) {
							queryParams.append('ip', ip);
						}

						try {
							// Use the experimental validation API endpoint
							const response = await makeBentoRequest.call(
								this,
								'POST',
								`/api/v1/experimental/validation?${queryParams.toString()}`,
								undefined, // No body for this endpoint
								i
							);

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
						} catch (error) {
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

/**
 * Helper function to make HTTP requests to Bento API
 * Uses n8n's built-in httpRequest helper with proper authentication
 */
async function makeBentoRequest(
		this: IExecuteFunctions,
		method: 'GET' | 'POST' | 'PUT' | 'DELETE',
		endpoint: string,
		body?: any,
		itemIndex: number = 0,
	): Promise<any> {
		// Get and validate credentials
		const credentials = await this.getCredentials('bentoApi');
		if (!credentials) {
			throw new NodeOperationError(this.getNode(), 'No credentials provided', {
				itemIndex,
			});
		}

		const { publishableKey, secretKey, siteUuid } = credentials;
		
		// Validate all required credentials are present and non-empty
		if (!publishableKey || typeof publishableKey !== 'string' || publishableKey.trim() === '') {
			throw new NodeOperationError(this.getNode(), 'Missing or invalid publishableKey in credentials', {
				itemIndex,
			});
		}
		
		if (!secretKey || typeof secretKey !== 'string' || secretKey.trim() === '') {
			throw new NodeOperationError(this.getNode(), 'Missing or invalid secretKey in credentials', {
				itemIndex,
			});
		}
		
		if (!siteUuid || typeof siteUuid !== 'string' || siteUuid.trim() === '') {
			throw new NodeOperationError(this.getNode(), 'Missing or invalid siteUuid in credentials', {
				itemIndex,
			});
		}

		// Type cast credentials to strings for safe usage
		const pubKey = publishableKey.trim();
		const secKey = secretKey.trim();
		const uuid = siteUuid.trim();


		// Create Basic auth header
		const authHeader = 'Basic ' + Buffer.from(`${pubKey}:${secKey}`).toString('base64');

		// Build the full URL with site_uuid parameter
		const baseUrl = 'https://app.bentonow.com';
		
		// Validate and encode the site_uuid
		if (!uuid || typeof uuid !== 'string' || uuid.trim() === '') {
			throw new NodeOperationError(this.getNode(), 'Invalid site_uuid in credentials - must be a non-empty string', {
				itemIndex,
			});
		}
		
		const encodedUuid = encodeURIComponent(uuid.trim());
		const separator = endpoint.includes('?') ? '&' : '?';
		const fullUrl = `${baseUrl}${endpoint}${separator}site_uuid=${encodedUuid}`;


		// Additional validation before making the request
		try {
			new URL(fullUrl); // This will throw if the URL is invalid
		} catch (urlError) {
			// Log the URL error securely
			logSecureError.call(this, urlError, 'URL Validation', {
				itemIndex,
				endpoint
			});
			
			throw new NodeOperationError(
				this.getNode(),
				SECURE_ERROR_MESSAGES.INVALID_REQUEST,
				{
					itemIndex,
				}
			);
		}

		try {
			const options: any = {
				method,
				url: fullUrl, // Changed from 'uri' to 'url' for n8n's httpRequest
				headers: {
					Authorization: authHeader,
					'Content-Type': 'application/json',
					Accept: 'application/json',
				},
				json: true,
			};

			// Add body for POST/PUT requests
			if (body && (method === 'POST' || method === 'PUT')) {
				options.body = body;
			}

			const response = await this.helpers.httpRequest(options);
			return response;

	} catch (error: any) {
		// Log the error securely for debugging
		logSecureError.call(this, error, 'API Request', {
			itemIndex,
			endpoint
		});
		
		// Create a secure error message
		const secureMessage = createSecureErrorMessage(error, 'API Request');
		
		// Create error with minimal information exposure
		const nodeError = new NodeOperationError(
			this.getNode(),
			secureMessage,
			{
				itemIndex,
				description: `Failed to communicate with Bento API. Status: ${error.statusCode || 'Unknown'}`,
			}
		);
		
		throw nodeError;
	}	}