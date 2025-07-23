# Bento n8n Community Node
<img align="right" src="https://app.bentonow.com/brand/logoanim.gif">

> [!TIP]
> Need help? Join our [Discord](https://discord.gg/ssXXFRmt5F) or email jesse@bentonow.com for personalized support.

The Bento n8n Community Node makes it quick and easy to integrate Bento's powerful email marketing and automation platform directly into your n8n workflows. Send transactional emails, track events, manage subscribers, and execute advanced subscriber commands - all without leaving your automation environment.

Get started with our [📚 integration guides](https://docs.bentonow.com), or [📘 browse the API reference](https://docs.bentonow.com/subscribers).


[![npm version](https://badge.fury.io/js/n8n-nodes-bento.svg)](https://badge.fury.io/js/n8n-nodes-bento)

Table of contents
=================

<!--ts-->
* [Features](#features)
* [Requirements](#requirements)
* [Getting started](#getting-started)
    * [Installation](#installation)
    * [Configuration](#configuration)
* [Operations](#operations)
* [Things to Know](#things-to-know)
* [Contributing](#contributing)
* [License](#license)
<!--te-->

## Features

* **Subscriber Management**: Create, update, and retrieve subscriber information with custom fields and tags
* **Event Tracking**: Track custom events and user behavior for advanced segmentation and automation
* **Transactional Emails**: Send personalized transactional emails with HTML/text content and template variables
* **Subscriber Commands**: Execute powerful commands like adding/removing tags, managing fields, and subscription status
* **Email Validation**: Validate email addresses for spam/throwaway detection using Bento's validation service
* **Security First**: Built-in input validation, HTML sanitization, and secure error handling
* **Rate Limiting**: Intelligent retry logic with exponential backoff for reliable API communication

## Requirements

- n8n version 0.198.0 or higher
- Node.js 20.15 or higher
- Bento account with API credentials

## Getting started

### Installation

#### Option 1: Install via n8n Community Nodes (Recommended)

1. Open your n8n instance
2. Go to **Settings** → **Community Nodes**
3. Click **Install a community node**
4. Enter the package name: `bento-n8n-sdk`
5. Click **Install**

#### Option 2: Install via npm (Self-hosted)

If you're running n8n locally or in a self-hosted environment:

```bash
# Navigate to your n8n installation directory
cd ~/.n8n

# Install the Bento community node
npm install bento-n8n-sdk

# Restart n8n
n8n start
```

#### Option 3: Docker Installation

For Docker installations, add the package to your n8n container:

```dockerfile
# In your Dockerfile or docker-compose.yml
FROM n8nio/n8n:latest

USER root
RUN npm install -g bento-n8n-sdk
USER node
```

Or using environment variables in docker-compose.yml:

```yaml
version: '3.8'
services:
  n8n:
    image: n8nio/n8n:latest
    environment:
      - N8N_NODES_INCLUDE=bento-n8n-sdk
```

### Configuration

After installation, you'll need to set up your Bento API credentials:

1. **Get your Bento API credentials:**
   - Log into your [Bento dashboard](https://app.bentonow.com)
   - Navigate to **API Keys**
   - Copy your **Publishable Key**, **Secret Key**, and **Site UUID**

2. **Configure credentials in n8n:**
   - In your n8n workflow, add a Bento node
   - Click on the **Credential for Bento API** dropdown
   - Select **Create New Credential**
   - Fill in your credentials:
     - **Publishable Key**: Your Bento publishable key (used for client-side operations)
     - **Secret Key**: Your Bento secret key (used for server-side operations - keep secure)
     - **Site UUID**: Your Bento site UUID (identifies your specific Bento site)
   - Click **Save** and **Test** to verify the connection

> **Security Note:**
> Your Secret Key is sensitive information. n8n automatically encrypts and securely stores your credentials. Never share your secret key or include it in version control.

## Operations

The Bento node supports the following operations:

### Create Subscriber

Add a new subscriber to your Bento audience with email and profile data.

**Required Parameters:**
- **Email**: The subscriber's email address

**Optional Parameters:**
- **First Name**: Subscriber's first name for personalization
- **Last Name**: Subscriber's last name for personalization  
- **Custom Fields**: Additional key-value pairs to store with the subscriber

**Example Use Cases:**
- Add new users from form submissions
- Import subscribers from external databases
- Create subscribers from webhook data

### Get Subscriber

Retrieve detailed information about an existing subscriber by email.

**Required Parameters:**
- **Email**: The subscriber's email address

**Returns:**
- Complete subscriber profile including custom fields, tags, and subscription status

**Example Use Cases:**
- Look up subscriber information before sending personalized content
- Verify subscriber existence in conditional workflows
- Retrieve custom field data for personalization

### Update Subscriber

Modify subscriber profile information and custom attributes.

**Required Parameters:**
- **Email**: The subscriber's email address

**Optional Parameters:**
- **First Name**: Updated first name
- **Last Name**: Updated last name
- **Custom Fields**: Updated or new custom field values

**Example Use Cases:**
- Update subscriber information from CRM changes
- Add new custom fields based on user behavior
- Sync subscriber data across platforms

### Track Event

Record custom events and behaviors for subscriber segmentation and automation.

**Required Parameters:**
- **User ID**: Unique identifier for the user (typically email address)
- **Event Name**: Name of the custom event (e.g., "purchase_completed", "page_viewed")

**Optional Parameters:**
- **Event Properties**: Additional key-value pairs with event data

**Example Use Cases:**
- Track purchase events with order details
- Record page views and user interactions
- Monitor feature usage and engagement
- Trigger automation based on user behavior

### Send Transactional Email

Send personalized transactional emails using HTML or text content.

**Required Parameters:**
- **Recipient Email**: Email address of the recipient
- **From Email**: Sender email address
- **Subject**: Email subject line
- **Email Type**: Choose between HTML or Text format

**Content Parameters:**
- **HTML Body**: HTML content (when Email Type is HTML)
- **Text Body**: Plain text content (when Email Type is Text)

**Optional Parameters:**
- **Transactional**: Mark as transactional email this ignores if the user has unsubscribed. USE WITH CAUTION!
- **Personalizations**: Template variables for dynamic content using liquid tags.

**Example Use Cases:**
- Send password reset emails
- Deliver order confirmations
- Send welcome emails to new users
- Notify users of account changes

### Subscriber Command

Execute commands on subscribers to manage tags, fields, and subscription status.

**Required Parameters:**
- **Email**: The subscriber's email address
- **Command**: The action to perform

**Available Commands:**
- **Add Tag**: Add a tag to the subscriber
- **Remove Tag**: Remove a tag from the subscriber
- **Add Tag via Event**: Add a tag through event tracking
- **Add Field**: Add or update a custom field
- **Remove Field**: Remove a custom field
- **Subscribe**: Subscribe the email address
- **Unsubscribe**: Unsubscribe the email address
- **Change Email**: Update the subscriber's email address

**Example Use Cases:**
- Segment subscribers with tags based on behavior
- Manage subscription preferences
- Update subscriber data programmatically
- Handle unsubscribe requests

### Validate Email

Validate email addresses for spam/throwaway detection using Bento's validation service.

**Required Parameters:**
- **Email**: The email address to validate

**Optional Parameters:**
- **Name**: Associated name (improves validation accuracy)
- **IP Address**: Associated IP address (improves validation accuracy)

**Returns:**
- Validation results including deliverability score and risk assessment

**Example Use Cases:**
- Filter out invalid emails before adding subscribers
- Prevent spam signups
- Improve email deliverability rates
- Validate email quality in real-time

## Things to Know

### Security & Validation

1. **Input Validation**: All inputs are validated for length, format, and security
2. **HTML Sanitization**: HTML content is automatically sanitized to prevent XSS attacks
3. **Email Validation**: Email addresses are validated using RFC-compliant regex patterns
4. **Secure Error Handling**: Error messages don't expose sensitive information

### Rate Limiting & Reliability

1. **Automatic Retries**: Failed requests are automatically retried with exponential backoff
2. **Rate Limiting**: Built-in rate limiting prevents API quota exhaustion
3. **Concurrent Requests**: Intelligent management of concurrent API requests
4. **Timeout Handling**: Configurable timeouts prevent hanging requests

### Best Practices

1. **Credential Security**: Always use n8n's credential system - never hardcode API keys
2. **Error Handling**: Use n8n's "Continue on Fail" option for robust workflows
3. **Batch Operations**: For large datasets, consider using multiple smaller batches
4. **Testing**: Always test your workflows in a development environment first

### API Endpoints Used

The node uses the following Bento API endpoints:
- `POST /api/v1/batch/events` - For creating subscribers and tracking events
- `GET /api/v1/fetch/subscribers` - For retrieving subscriber information
- `POST /api/v1/batch/subscribers` - For updating subscriber information
- `POST /api/v1/batch/emails` - For sending transactional emails
- `POST /api/v1/fetch/commands` - For executing subscriber commands
- `POST /api/v1/experimental/validation` - For email validation

### Limitations

1. **Payload Size**: Maximum request payload size is 1MB
2. **Concurrent Requests**: Limited to 5 concurrent requests per node instance
3. **HTML Content**: Dangerous HTML elements are automatically removed for security
4. **Field Limits**: Custom field keys are limited to 50 characters, values to 500 characters

### Troubleshooting

**Common Issues:**

1. **Authentication Failed**: Verify your API credentials are correct and active
2. **Invalid Email Format**: Ensure email addresses follow RFC standards
3. **Rate Limited**: Reduce request frequency or implement delays between operations
4. **HTML Validation Failed**: Check for dangerous HTML elements in email content

**Getting Help:**

- Check the [Bento API Documentation](https://docs.bentonow.com)
- Join our [Discord community](https://discord.gg/ssXXFRmt5F)
- Email support: jesse@bentonow.com

## Contributing

We welcome contributions! Please see our [contributing guidelines](CODE_OF_CONDUCT.md) for details on how to submit pull requests, report issues, and suggest improvements.

### Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/bentonow/bento-n8n-sdk.git
   cd bento-n8n-sdk
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the project:
   ```bash
   npm run build
   ```

4. Run linting:
   ```bash
   npm run lint
   ```

5. Link for local testing:
   ```bash
   npm link
   cd ~/.n8n
   npm link bento-n8n-sdk
   ```

## License

The Bento n8n Community Node is available as open source under the terms of the [MIT License](LICENSE.md).
