# Bento n8n SDK - Beginner's Guide

Welcome to the Bento n8n SDK! This guide will help you get started with integrating Bento's email marketing platform into your n8n workflows.

## What is Bento?

Bento is an email marketing and automation platform that helps you:
- Send transactional emails and broadcasts
- Manage subscribers and segments
- Track user events and behavior
- Create automated marketing workflows

## Prerequisites

Before you start, make sure you have:
- An active Bento account ([sign up here](https://bentonow.com))
- Your Bento API credentials
- A working n8n instance (self-hosted or cloud)

## Getting Your Bento API Credentials

1. **Log into your Bento dashboard** at [app.bentonow.com](https://app.bentonow.com)
2. Navigate to **Settings** → **API Keys**
3. You'll find three important values:
   - **Publishable Key**: Starts with `pk_` (for client-side operations)
   - **Secret Key**: Starts with `sk_` (for server-side operations)
   - **Site UUID**: Your unique site identifier

4. **Copy all three values** - you'll need them for n8n setup

## Setting Up Bento in n8n

### Step 1: Install the Bento Nodes

If you're using n8n locally:
```bash
npm install n8n-nodes-bento
```

Or use the Docker installation method (recommended for production).

### Step 2: Create Bento Credentials

1. In n8n, go to **Credentials** → **Add Credential**
2. Search for "Bento API" and select it
3. Fill in your credentials:
   - **Publishable Key**: Your `pk_` key from Bento
   - **Secret Key**: Your `sk_` key from Bento  
   - **Site UUID**: Your site UUID from Bento
4. Click **Save** and test the connection

### Step 3: Start Using Bento Nodes

Now you can add Bento nodes to your workflows! Here are the most common ones for beginners:

## Common Use Cases for Beginners

### 1. Adding a New Subscriber

**When to use:** Someone signs up on your website or form

**Workflow:**
1. **Trigger** (Webhook, Form, etc.)
2. **Bento Node** → **Create Subscriber**
   - Email: `{{ $json.email }}`
   - First Name: `{{ $json.firstName }}`
   - Last Name: `{{ $json.lastName }}`

### 2. Sending a Welcome Email

**When to use:** New subscriber joins your list

**Workflow:**
1. **Trigger** (Bento webhook on new subscriber)
2. **Bento Node** → **Send Transactional Email**
   - To Email: `{{ $json.email }}`
   - Subject: "Welcome to our newsletter!"
   - HTML Body: Your welcome email template

### 3. Tracking User Actions

**When to use:** User performs an action on your site

**Workflow:**
1. **Trigger** (Webhook from your app)
2. **Bento Node** → **Track Event**
   - Email: `{{ $json.userEmail }}`
   - Event Name: `{{ $json.eventName }}`
   - Event Data: `{{ $json.eventData }}`

## Understanding the Basic Operations

### Subscriber Management
- **Create Subscriber**: Add new people to your email list
- **Get Subscriber**: Look up subscriber information
- **Update Subscriber**: Change subscriber details
- **Subscriber Command**: Perform actions like adding tags or unsubscribing

### Email Operations
- **Send Transactional Email**: Send individual emails (password resets, notifications, etc.)
- **Send Broadcast**: Send emails to multiple subscribers at once

### Analytics
- **Site Metrics**: See overall performance stats
- **Track Event**: Record user actions for better targeting

## Pro Tips for Beginners

### Email Validation
The SDK automatically validates email addresses, but make sure you're passing clean email data:
```javascript
// Good
email: "user@example.com"

// Bad - will be rejected
email: "invalid-email"
email: "user@.com"
```

### Using Personalization
In your email templates, you can use Bento's personalization variables:
```html
Hi {{ subscriber.first_name }},

Thanks for joining {{ site.name }}!
```

### Error Handling
Always check if operations succeed:
- Use n8n's built-in error handling
- Check the node output for success/failure status
- Set up fallback actions for failed operations

### Testing Your Workflows
1. Use the **Execute Node** feature to test individual nodes
2. Start with small batches of subscribers
3. Monitor your Bento dashboard for results

## Common Issues and Solutions

### "Invalid Credentials" Error
- Double-check all three credential fields
- Make sure you copied the complete keys (no extra spaces)
- Verify your keys are active in Bento

### "Subscriber Not Found" 
- Check if the email exists in your Bento account
- Verify the email format is correct
- Use the Get Subscriber node first to check

### "Email Send Failed"
- Check your HTML content for invalid tags
- Verify the recipient email is valid
- Check your Bento sending limits

## Next Steps

Once you're comfortable with the basics, explore:
- **Advanced segmentation** using tags and custom fields
- **Automated workflows** with multiple Bento nodes
- **Analytics and reporting** to track performance
- **Experimental features** like email validation and geolocation

## Getting Help

If you run into issues:
1. Check the [n8n community forums](https://community.n8n.io)
2. Review the [Power User Guide](./power-user-guide.md) for advanced topics
3. Contact Bento support at [support@bentonow.com](mailto:support@bentonow.com)
4. Check the [GitHub repository](https://github.com/bentonow/bento-n8n-sdk) for known issues

---

**Happy automating!**

You now have everything you need to start building powerful email automation workflows with Bento and n8n.