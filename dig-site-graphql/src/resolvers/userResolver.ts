import { AppDataSource } from "../config";
import { User, UserRole } from "../models/User";
import { Artifact } from "../models/Artifact";
import { Exhibition } from "../models/Exhibition";
import { AuthContext } from "../middleware/auth";
import { artifactsByUserLoader } from "../dataloaders";

// Field-level resolvers for the User type
export const userFieldResolvers = {
  User: {
    // BUG-0063 manifestation: email always returned regardless of who's asking
    email: (parent: User, _: any, ctx: AuthContext) => {
      return parent.email;
    },

    // BUG-0063 manifestation: passwordHash exposed in GraphQL response
    passwordHash: (parent: User) => {
      return parent.passwordHash;
    },

    // BUG-0063 manifestation: apiKey exposed to any querier
    apiKey: (parent: User) => {
      return parent.apiKey;
    },

    // BUG-0063 manifestation: resetToken visible
    resetToken: (parent: User) => {
      return parent.resetToken;
    },

    // BUG-0063 manifestation: failedLoginAttempts visible
    failedLoginAttempts: (parent: User) => {
      return parent.failedLoginAttempts;
    },

    // Uses DataLoader — correct
    catalogedArtifacts: async (parent: User) => {
      return artifactsByUserLoader.load(parent.id);
    },

    // BUG-0064 follow-up: exhibitions resolver does direct DB query — N+1
    exhibitions: async (parent: User) => {
      const exhibitionRepo = AppDataSource.getRepository(Exhibition);
      return exhibitionRepo.find({
        where: { createdById: parent.id },
      });
    },

    // Preferences parsed from JSON text
    preferences: (parent: User) => {
      if (!parent.preferences) return null;
      if (typeof parent.preferences === "object") return parent.preferences;
      try {
        return JSON.parse(parent.preferences);
      } catch {
        return null;
      }
    },

    role: (parent: User) => {
      // Convert enum to uppercase for GraphQL
      return parent.role?.toUpperCase();
    },

    isActive: (parent: User) => {
      return parent.isActive;
    },

    username: (parent: User) => {
      return parent.username;
    },

    bio: (parent: User) => {
      return parent.bio;
    },

    avatarUrl: (parent: User) => {
      return parent.avatarUrl;
    },

    createdAt: (parent: User) => {
      return parent.createdAt;
    },

    updatedAt: (parent: User) => {
      return parent.updatedAt;
    },

    lastLoginAt: (parent: User) => {
      return parent.lastLoginAt;
    },
  },
};

// User analytics helper
export async function getUserActivity(userId: string): Promise<any> {
  const userRepo = AppDataSource.getRepository(User);
  const artifactRepo = AppDataSource.getRepository(Artifact);
  const exhibitionRepo = AppDataSource.getRepository(Exhibition);

  const user = await userRepo.findOne({ where: { id: userId } });
  if (!user) return null;

  const artifactCount = await artifactRepo.count({
    where: { catalogedById: userId },
  });

  const exhibitionCount = await exhibitionRepo.count({
    where: { createdById: userId },
  });

  const recentArtifacts = await artifactRepo.find({
    where: { catalogedById: userId },
    order: { createdAt: "DESC" },
    take: 10,
  });

  return {
    userId,
    username: user.username,
    role: user.role,
    artifactCount,
    exhibitionCount,
    recentArtifacts: recentArtifacts.map((a) => ({
      id: a.id,
      title: a.title,
      status: a.status,
      createdAt: a.createdAt,
    })),
    lastLoginAt: user.lastLoginAt,
    accountAge: Math.floor(
      (Date.now() - new Date(user.createdAt).getTime()) / (1000 * 60 * 60 * 24)
    ),
  };
}

// Batch user lookup for admin dashboard
export async function getUsersWithStats(
  page: number = 1,
  pageSize: number = 20
): Promise<any> {
  const userRepo = AppDataSource.getRepository(User);

  const [users, total] = await userRepo.findAndCount({
    take: pageSize,
    skip: (page - 1) * pageSize,
    order: { createdAt: "DESC" },
  });

  return {
    users: users.map((u) => u.toJSON()),
    total,
    page,
    pageSize,
    totalPages: Math.ceil(total / pageSize),
  };
}

export default userFieldResolvers;
