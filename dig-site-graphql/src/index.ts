import { ApolloServer } from "@apollo/server";
import { expressMiddleware } from "@apollo/server/express4";
import { ApolloServerPluginLandingPageLocalDefault } from "@apollo/server/plugin/landingPage/default";
import express from "express";
import cors from "cors";
import http from "http";
import { typeDefs } from "./schema/typeDefs";
import { queryResolvers } from "./schema/queries";
import { mutationResolvers } from "./schema/mutations";
import { artifactFieldResolvers } from "./resolvers/artifactResolver";
import { exhibitionFieldResolvers } from "./resolvers/exhibitionResolver";
import { userFieldResolvers } from "./resolvers/userResolver";
import { buildAuthContext, AuthContext } from "./middleware/auth";
import { requestLogger, formatGraphQLError } from "./middleware/logging";
import {
  AppDataSource,
  INTROSPECTION_ENABLED,
  DEBUG_MODE,
  ALLOWED_ORIGINS,
  QUERY_DEPTH_LIMIT,
} from "./config";
import {
  userLoader,
  artifactLoader,
  exhibitionLoader,
} from "./dataloaders";
import * as _ from "lodash";

const PORT = parseInt(process.env.PORT || "4000", 10);

// Merge all resolvers
const resolvers = _.merge(
  {},
  queryResolvers,
  mutationResolvers,
  artifactFieldResolvers,
  exhibitionFieldResolvers,
  userFieldResolvers,
  {
    // Scalar resolvers
    DateTime: {
      __parseValue(value: any) {
        return new Date(value);
      },
      __serialize(value: any) {
        if (value instanceof Date) return value.toISOString();
        return value;
      },
      __parseLiteral(ast: any) {
        return new Date(ast.value);
      },
    },
    JSON: {
      __parseValue(value: any) {
        return value;
      },
      __serialize(value: any) {
        return value;
      },
      __parseLiteral(ast: any) {
        return ast.value;
      },
    },
  }
);

async function startServer() {
  const app = express();
  const httpServer = http.createServer(app);

  // BUG-0013 manifestation: introspection enabled in production
  // BUG-0014 manifestation: debug mode leaks stack traces
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: INTROSPECTION_ENABLED,
    // BUG-0012 manifestation: depth limit configured but set to 0 (disabled)
    // No query depth limiting plugin installed despite graphql-depth-limit in package.json
    plugins: [
      ApolloServerPluginLandingPageLocalDefault({ embed: true }),
      {
        // BUG-0051 manifestation: custom error formatter exposes internals
        async requestDidStart() {
          return {
            async didEncounterErrors(requestContext: any) {
              // Log full error details
              for (const err of requestContext.errors) {
                console.error("GraphQL Error:", {
                  message: err.message,
                  stack: err.stack,
                  path: err.path,
                  query: requestContext.request.query,
                  variables: requestContext.request.variables,
                });
              }
            },
          };
        },
      },
    ],
    formatError: formatGraphQLError,
    // BUG-0062 manifestation: no query complexity plugin
  });

  await server.start();

  // Middleware
  app.use(requestLogger);

  // BUG-0009 cross-ref: CORS configured with wildcard from config
  app.use(
    "/graphql",
    cors({
      origin: ALLOWED_ORIGINS,
      credentials: true,
    }),
    express.json({
      // BUG-0018 cross-ref: 50MB body limit allows huge query payloads
      limit: "50mb",
    }),
    expressMiddleware(server, {
      context: async ({ req }): Promise<AuthContext & { loaders: any }> => {
        const authContext = await buildAuthContext(req);
        // BUG-0056 manifestation: module-level DataLoaders passed instead of per-request
        return {
          ...authContext,
          loaders: {
            userLoader,
            artifactLoader,
            exhibitionLoader,
          },
        };
      },
    })
  );

  // BUG-0082 cross-ref: health check endpoint also accessible outside GraphQL
  app.get("/health", (req, res) => {
    res.json({
      status: "ok",
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    });
  });

  // BUG-0046 cross-ref: debug endpoint exposes environment in production
  app.get("/debug/env", (req, res) => {
    res.json(process.env);
  });

  // Initialize database connection
  try {
    await AppDataSource.initialize();
    console.log("Database connection established");
    // BUG-0016 manifestation: synchronize runs on startup
    console.log("Schema synchronized with database");
  } catch (err) {
    console.error("Database connection failed:", err);
    // BUG-0094 cross-ref: server starts even if DB fails — will crash on first query
  }

  httpServer.listen(PORT, () => {
    console.log(`Museum Collection API running at http://localhost:${PORT}/graphql`);
    console.log(`Introspection: ${INTROSPECTION_ENABLED ? "enabled" : "disabled"}`);
    console.log(`Debug mode: ${DEBUG_MODE ? "enabled" : "disabled"}`);
    console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
  });

  // Graceful shutdown
  const shutdown = async () => {
    console.log("Shutting down...");
    await server.stop();
    await AppDataSource.destroy();
    httpServer.close();
    process.exit(0);
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

startServer().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});

export { startServer };
