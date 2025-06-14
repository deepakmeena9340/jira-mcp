import express, { Request, Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import dotenv from 'dotenv';
import {
	formatProjectDetails,
} from './formatter.js';


const API_PATH = '/rest/api/3';

export interface AtlassianCredentials {
	siteName: string;
	userEmail: string;
	apiToken: string;
}

export interface RequestOptions {
	method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
	headers?: Record<string, string>;
	body?: unknown;
}

export interface ControllerResponse {
	content: string;
}

export interface GetProjectByIdParams {
	expand?: string[];
	includeComponents?: boolean;
	includeVersions?: boolean;
	includeProperties?: boolean;
}

const PaginationArgs = {
	limit: z
		.number()
		.min(1)
		.max(100)
		.optional()
		.describe(
			'Maximum number of items to return (1-100). Use this to control the response size. Useful for pagination or when you only need a few results.',
		),

	startAt: z
		.number()
		.int()
		.nonnegative()
		.optional()
		.describe(
			'Index of the first item to return (0-based offset). Use this for pagination instead of cursor, as Jira uses offset-based pagination.',
		),
};

const GetProjectToolArgs = z.object({
	/**
	 * Project key or numeric ID
	 */
	projectKeyOrId: z
		.string()
		.describe(
			'The key or numeric ID of the Jira project to retrieve (e.g., "PROJ" or "10001"). This is required and must be a valid project key or ID from your Jira instance.',
		),
});

type GetProjectToolArgsType = z.infer<typeof GetProjectToolArgs>;

const ListProjectsToolArgs = z.object({
	/**
	 * Filter by project name or key
	 */
	name: z
		.string()
		.optional()
		.describe(
			'Filter projects by name or key (case-insensitive). Use this to find specific projects by their display name or project key.',
		),

	/**
	 * Maximum number of projects to return and pagination
	 */
	...PaginationArgs,

	/**
	 * Field to sort the projects by
	 */
	orderBy: z
		.string()
		.optional()
		.describe(
			'Field to sort projects by (e.g., "name", "key", "lastIssueUpdatedTime"). Default is "lastIssueUpdatedTime", which shows the most recently active projects first.',
		),
});

type ListProjectsToolArgsType = z.infer<typeof ListProjectsToolArgs>;

const ProjectStyleSchema = z.enum(['classic', 'next-gen']);

const ProjectAvatarUrlsSchema = z.object({
	'16x16': z.string().url(),
	'24x24': z.string().url(),
	'32x32': z.string().url(),
	'48x48': z.string().url(),
});

const ProjectInsightSchema = z.object({
	lastIssueUpdateTime: z.string(),
	totalIssueCount: z.number(),
});

const ProjectCategorySchema = z.object({
	id: z.string(),
	name: z.string(),
	description: z.string().optional(),
	self: z.string().url(),
});



const ProjectSchema = z.object({
	id: z.string(),
	key: z.string(),
	name: z.string(),
	self: z.string().url(),
	simplified: z.boolean(),
	style: ProjectStyleSchema,
	avatarUrls: ProjectAvatarUrlsSchema,
	insight: ProjectInsightSchema.optional(),
	projectCategory: ProjectCategorySchema.optional(),
});

const ProjectComponentSchema = z.object({
	id: z.string(),
	name: z.string(),
	description: z.string().optional(),
	lead: z
		.object({
			id: z.string(),
			displayName: z.string(),
		})
		.optional(),
	assigneeType: z.string().optional(),
	assignee: z
		.object({
			id: z.string(),
			displayName: z.string(),
		})
		.optional(),
	self: z.string().url(),
});

const ProjectVersionSchema = z.object({
	id: z.string(),
	name: z.string(),
	description: z.string().optional(),
	archived: z.boolean(),
	released: z.boolean(),
	releaseDate: z.string().optional(),
	startDate: z.string().optional(),
	self: z.string().url(),
});

export type Project = z.infer<typeof ProjectSchema>;

const ProjectDetailedSchema = ProjectSchema.extend({
	description: z.string().optional(),
	lead: z
		.object({
			id: z.string().optional(),
			displayName: z.string(),
			active: z.boolean(),
			self: z.string().optional(),
			accountId: z.string().optional(),
			avatarUrls: z.record(z.string()).optional(),
		})
		.optional(),
	components: z.array(ProjectComponentSchema),
	versions: z.array(ProjectVersionSchema),
	properties: z
		.object({
			results: z.array(z.any()).optional(),
			meta: z.any().optional(),
			_links: z.any().optional(),
		})
		.optional(),
});
export type ProjectDetailed = z.infer<typeof ProjectDetailedSchema>;

export function loadFromEnvFile() {
	try {
		const result = dotenv.config();
		console.debug(result);
		if (result.error) {
			console.debug(
				'No .env file found or error reading it',
			);
			return;
		}
		console.debug(
			'Loaded configuration from .env file',
		);
	} catch (error) {
		console.error(
			'Error loading .env file',
			error,
		);
	}
}

export const skipValidation = process.env.NODE_ENV === 'test';

export function validateResponse<T, S>(
	data: unknown,
	schema: z.ZodType<T, z.ZodTypeDef, S>,
	context: string,
	serviceIdentifier?: string,
): T {
	const logPrefix = serviceIdentifier ? `[${serviceIdentifier}] ` : '';

	// Skip validation in test environment if the flag is set
	if (skipValidation) {
		console.debug(
			`${logPrefix}Skipping validation for ${context} in test environment`,
		);
		return data as T;
	}

	try {
		console.debug(`${logPrefix}Validating response for ${context}`);
		return schema.parse(data);
	} catch (error) {
		if (error instanceof z.ZodError) {
			console.error(
				`${logPrefix}Response validation failed for ${context}:`,
				error.format(),
			);
			throw new Error(
				`API response validation failed: Invalid Jira ${context} format: ${error.format()}`,
			);
		}
		// Re-throw if it's not a Zod error
		console.error(
			`${logPrefix}Non-Zod error during validation for ${context}: ${error}`,
		);
		throw error;
	}
}

export function getAtlassianCredentials(): AtlassianCredentials | null {
	const siteName = process.env['ATLASSIAN_SITE_NAME'] || "";
	const userEmail = process.env['ATLASSIAN_USER_EMAIL'] || "";
	const apiToken = process.env['ATLASSIAN_API_TOKEN'] || "";

	if (!siteName || !userEmail || !apiToken) {
		console.warn(
			'Missing Atlassian credentials. Please set ATLASSIAN_SITE_NAME, ATLASSIAN_USER_EMAIL, and ATLASSIAN_API_TOKEN environment variables.',
		);
		return null;
	}

	console.debug('Using Atlassian credentials');
	return {
		siteName,
		userEmail,
		apiToken,
	};
}

export async function fetchAtlassian<T>(
	credentials: AtlassianCredentials,
	path: string,
	options: RequestOptions = {},
): Promise<T> {
	const { siteName, userEmail, apiToken } = credentials;

	// Ensure path starts with a slash
	const normalizedPath = path.startsWith('/') ? path : `/${path}`;

	// Construct the full URL
	const baseUrl = `https://${siteName}.atlassian.net`;
	const url = `${baseUrl}${normalizedPath}`;

	// Set up authentication and headers
	const headers = {
		Authorization: `Basic ${Buffer.from(`${userEmail}:${apiToken}`).toString('base64')}`,
		'Content-Type': 'application/json',
		Accept: 'application/json',
		...options.headers,
	};

	// Prepare request options
	const requestOptions: RequestInit = {
		method: options.method || 'GET',
		headers,
		body: options.body ? JSON.stringify(options.body) : undefined,
	};

	try {
		console.debug(url, requestOptions);
		const response = await fetch(url, requestOptions);

		if (!response.ok) {
			const errorText = await response.text();
			console.error(`Jira API Response Error: ${errorText}`);
		}

		console.debug(`Response Status: ${response.statusText}-${response.status}`);

		// Clone the response to log its content without consuming it
		const clonedResponse = response.clone();
		try {
			const responseJson = await clonedResponse.json();
		} catch (error) {
			throw new Error(
				`Jira API Response Error: JSON parsing failed`
			);
		}

		return response.json() as Promise<T>;
	} catch (error) {
		throw new Error(
			`Unexpected error while calling Jira API: ${error instanceof Error ? error.message : String(error)}`
		);
	}
}

async function getJiraProjectService(
	idOrKey: string,
	params: GetProjectByIdParams = {},
): Promise<ProjectDetailed> {
	console.debug(
		`Getting Jira project with ID/key: ${idOrKey}, params:`,
		params,
	);

	const credentials = getAtlassianCredentials();
	if (!credentials) {
		throw new Error(`Get project ${idOrKey}`);
	}

	// Build query parameters
	const queryParams = new URLSearchParams();

	// Build expand parameter
	const expandItems: string[] = params.expand || [];
	if (params.includeComponents) {
		expandItems.push('components');
	}
	if (params.includeVersions) {
		expandItems.push('versions');
	}
	if (params.includeProperties) {
		expandItems.push('properties');
	}

	if (expandItems.length > 0) {
		queryParams.set('expand', expandItems.join(','));
	}

	const queryString = queryParams.toString()
		? `?${queryParams.toString()}`
		: '';
	const path = `${API_PATH}/project/${idOrKey}${queryString}`;

	console.debug(`Calling Jira API: ${path}`);

	try {
		const rawData = await fetchAtlassian(credentials, path);
		console.debug(rawData);
		return validateResponse(
			rawData,
			ProjectDetailedSchema,
			`project ${idOrKey}`,
			'projects.service',
		);
	} catch (error) {
		console.error(
			`Unexpected error getting project ${idOrKey}:`,
			error,
		);

		throw new Error(
			`Unexpected error retrieving Jira project ${idOrKey}: ${error instanceof Error ? error.message : String(error)}`,
		);
	}
}


async function getJiraProject(
	identifier: GetProjectToolArgsType,
): Promise<ControllerResponse> {
	const { projectKeyOrId } = identifier;

	console.debug(
		`Getting Jira project with key/ID: ${projectKeyOrId}...`,
	);

	// Validate project key/ID format
	if (!projectKeyOrId || projectKeyOrId === 'invalid') {
		throw new Error('Invalid project key or ID');
	}

	try {
		// Create defaults object for get operation
		const defaults = {
			includeComponents: true,
			includeVersions: true,
		};

		// Always include all possible expansions for maximum detail
		const serviceParams = defaults;

		const projectData = await getJiraProjectService(
			projectKeyOrId,
			serviceParams,
		);
		// Log only key information instead of the entire response
		console.debug(
			`Retrieved project: ${projectData.name} (${projectData.id})`,
		);

		// Format the project data for display using the formatter
		const formattedProject = formatProjectDetails(projectData);

		return {
			content: formattedProject,
		};
	} catch (error) {
		// Use throw instead of return
		throw new Error(`Error getting jira project with key/ID: ${projectKeyOrId}...`);
	}
}

async function getProject(args: GetProjectToolArgsType) {
	console.debug(
		`Retrieving project details for key/ID: ${args.projectKeyOrId}`,
	);

	try {
		// Pass args directly to the controller
		const result = await getJiraProject(args);
		console.debug(
			'Successfully retrieved project details from controller',
		);

		return {
			content: [
				{
					type: 'text' as const,
					text: result.content,
				},
			],
		};
	} catch (error) {
		console.error('Failed to get project details', error);
		return {
			content: [{ type: 'text' as const, text: `Error getting jira project with key/ID: ${args.projectKeyOrId}` }],
		};
	}
}


const server = new McpServer({
	name: "mcp-streamable-http",
	version: "1.0.0",
});

const getJiraProjectTool = server.tool(
	'jira_get_project',
	`Retrieves comprehensive details for a specific Jira project using its key or ID (\`projectKeyOrId\`). Includes description, lead, components, versions, and other metadata. Use this after finding a project key/ID via \`jira_list_projects\` to get its full details. Returns detailed project information formatted as Markdown. Requires Jira credentials to be configured.`,
	GetProjectToolArgs.shape,
	getProject,
);



// Get Chuck Norris joke tool
const getChuckJoke = server.tool(
	"get-chuck-joke",
	"Get a random Chuck Norris joke",
	async () => {
		const response = await fetch("https://api.chucknorris.io/jokes/random");
		const data = await response.json();
		return {
			content: [
				{
					type: "text",
					text: data.value,
				},
			],
		};
	}
);

// Get Chuck Norris joke by category tool
const getChuckJokeByCategory = server.tool(
	"get-chuck-joke-by-category",
	"Get a random Chuck Norris joke by category",
	{
		category: z.string().describe("Category of the Chuck Norris joke"),
	},
	async (params: { category: string }) => {
		const response = await fetch(
			`https://api.chucknorris.io/jokes/random?category=${params.category}`
		);
		const data = await response.json();
		return {
			content: [
				{
					type: "text",
					text: data.value,
				},
			],
		};
	}
);

// Get Chuck Norris joke categories tool
const getChuckCategories = server.tool(
	"get-chuck-categories",
	"Get all available categories for Chuck Norris jokes",
	async () => {
		const response = await fetch("https://api.chucknorris.io/jokes/categories");
		const data = await response.json();
		return {
			content: [
				{
					type: "text",
					text: data.join(", "),
				},
			],
		};
	}
);

// Get Dad joke tool
const getDadJoke = server.tool(
	"get-dad-joke",
	"Get a random dad joke",
	async () => {
		const response = await fetch("https://icanhazdadjoke.com/", {
			headers: {
				Accept: "application/json",
			},
		});
		const data = await response.json();
		return {
			content: [
				{
					type: "text",
					text: data.joke,
				},
			],
		};
	}
);

loadFromEnvFile();
const app = express();
app.use(express.json());

const transport: StreamableHTTPServerTransport =
	new StreamableHTTPServerTransport({
		sessionIdGenerator: undefined, // set to undefined for stateless servers
	});

// Setup routes for the server
const setupServer = async () => {
	await server.connect(transport);
};

app.post("/mcp", async (req: Request, res: Response) => {
	console.log("Received MCP request:", req.body);
	try {
		await transport.handleRequest(req, res, req.body);
	} catch (error) {
		console.error("Error handling MCP request:", error);
		if (!res.headersSent) {
			res.status(500).json({
				jsonrpc: "2.0",
				error: {
					code: -32603,
					message: "Internal server error",
				},
				id: null,
			});
		}
	}
});

app.get("/mcp", async (req: Request, res: Response) => {
	console.log("Received GET MCP request");
	res.writeHead(405).end(
		JSON.stringify({
			jsonrpc: "2.0",
			error: {
				code: -32000,
				message: "Method not allowed.",
			},
			id: null,
		})
	);
});

app.delete("/mcp", async (req: Request, res: Response) => {
	console.log("Received DELETE MCP request");
	res.writeHead(405).end(
		JSON.stringify({
			jsonrpc: "2.0",
			error: {
				code: -32000,
				message: "Method not allowed.",
			},
			id: null,
		})
	);
});

// Start the server
const PORT = process.env.PORT || 3000;
setupServer()
	.then(() => {
		app.listen(PORT, () => {
			console.log(`MCP Streamable HTTP Server listening on port ${PORT}`);
		});
	})
	.catch((error) => {
		console.error("Failed to set up the server:", error);
		process.exit(1);
	});
