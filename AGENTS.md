# Agent Guidelines for Bento n8n SDK

## Build/Lint/Test Commands
- `npm run build` - Build TypeScript and copy icons to dist/
- `npm run dev` - Watch mode for TypeScript compilation
- `npm run lint` - ESLint check for nodes, credentials, package.json
- `npm run lintfix` - Auto-fix ESLint issues
- `npm run format` - Format code with Prettier
- `npm run prepublishOnly` - Full build + lint check before publish
- No test command available - this is an n8n community node package

## Code Style Guidelines
- **Formatting**: Use tabs (tabWidth: 2), single quotes, trailing commas, 100 char line width
- **TypeScript**: Strict mode enabled, target ES2019, use proper type imports from 'n8n-workflow'
- **Imports**: Group type imports separately using `import type { ... }`
- **Naming**: camelCase for variables/functions, PascalCase for classes, kebab-case for files
- **Error Handling**: Use NodeOperationError with itemIndex for user-facing errors
- **Validation**: Always validate email formats using regex, check required fields
- **Comments**: Use JSDoc for functions, inline comments for complex logic
- **n8n Conventions**: Follow n8n-nodes-base ESLint rules, use proper node descriptions
- **API Calls**: Use makeBentoRequest helper function with proper error handling
- **Credentials**: Always validate all credential fields (publishableKey, secretKey, siteUuid)
- **File Structure**: nodes/ for node implementations, credentials/ for auth configs