import { AppDataSource } from "../config";
import { Artifact, ArtifactStatus } from "../models/Artifact";
import { Exhibition } from "../models/Exhibition";
import { User, UserRole, generateApiKey } from "../models/User";
import { AuthContext, generateToken, generateResetToken } from "../middleware/auth";
import { auditLog } from "../middleware/logging";
import * as xml2js from "xml2js";
import * as bcrypt from "bcryptjs";
import { BCRYPT_ROUNDS } from "../config";

export const mutationResolvers = {
  Mutation: {
    // ─── Auth ────────────────────────────────────────────
    register: async (_: any, { input }: { input: any }) => {
      const userRepo = AppDataSource.getRepository(User);

      // BUG-0084: No email format validation (CWE-20, CVSS 3.7, LOW, Tier 3)
      // BUG-0085: No password strength validation — accepts empty or single-char passwords (CWE-521, CVSS 5.3, BEST_PRACTICE, Tier 2)
      const existingUser = await userRepo.findOne({ where: { email: input.email } });
      if (existingUser) {
        throw new Error("Email already registered");
      }

      const user = userRepo.create({
        email: input.email,
        username: input.username,
        passwordHash: input.password,
        bio: input.bio,
        // BUG-0069 manifests here: role from input is used directly
        role: input.role || UserRole.PUBLIC,
      });

      await userRepo.save(user);
      const token = generateToken(user);

      auditLog("USER_REGISTERED", user.id, { email: user.email, role: user.role });

      return { token, user };
    },

    login: async (_: any, { input }: { input: { email: string; password: string } }) => {
      const userRepo = AppDataSource.getRepository(User);
      const user = await userRepo.findOne({ where: { email: input.email } });

      if (!user) {
        // BUG-0086: Different error messages for invalid email vs invalid password — user enumeration (CWE-203, CVSS 5.3, TRICKY, Tier 2)
        throw new Error("No account found with that email");
      }

      const valid = await user.validatePassword(input.password);
      if (!valid) {
        // BUG-0025 manifests: failedLoginAttempts incremented but never checked/locked
        user.failedLoginAttempts += 1;
        await userRepo.save(user);
        throw new Error("Invalid password");
      }

      // Reset failed attempts on success
      user.failedLoginAttempts = 0;
      user.lastLoginAt = new Date();
      await userRepo.save(user);

      const token = generateToken(user);
      auditLog("USER_LOGIN", user.id, { email: user.email });

      return { token, user };
    },

    refreshToken: async (_: any, __: any, ctx: AuthContext) => {
      if (!ctx.isAuthenticated || !ctx.user) {
        throw new Error("Not authenticated");
      }
      // BUG-0087: Token refresh doesn't invalidate old token — both old and new tokens remain valid (CWE-613, CVSS 6.5, TRICKY, Tier 2)
      const newToken = generateToken(ctx.user);
      return { token: newToken, user: ctx.user };
    },

    resetPassword: async (_: any, { email }: { email: string }) => {
      const userRepo = AppDataSource.getRepository(User);
      const user = await userRepo.findOne({ where: { email } });

      if (user) {
        // BUG-0045 manifests here: predictable reset token
        user.resetToken = generateResetToken(user);
        await userRepo.save(user);
        // In production, would send email
        // BUG-0088: Reset token returned in response instead of sent via email (CWE-640, CVSS 8.0, CRITICAL, Tier 1)
        console.log(`Reset token for ${email}: ${user.resetToken}`);
      }

      // Always return true to prevent enumeration
      return true;
    },

    changePassword: async (
      _: any,
      { oldPassword, newPassword }: { oldPassword: string; newPassword: string },
      ctx: AuthContext
    ) => {
      if (!ctx.isAuthenticated || !ctx.user) {
        throw new Error("Not authenticated");
      }

      const userRepo = AppDataSource.getRepository(User);
      const user = await userRepo.findOne({ where: { id: ctx.user.id } });
      if (!user) throw new Error("User not found");

      const valid = await user.validatePassword(oldPassword);
      if (!valid) throw new Error("Current password is incorrect");

      // BUG-0089: New password not hashed — stored in plaintext because BeforeInsert hook only runs on insert (CWE-256, CVSS 9.0, CRITICAL, Tier 1)
      user.passwordHash = newPassword;
      await userRepo.save(user);

      auditLog("PASSWORD_CHANGED", user.id, {});
      return true;
    },

    // ─── Artifacts ───────────────────────────────────────
    createArtifact: async (_: any, { input }: { input: any }, ctx: AuthContext) => {
      // BUG-0090: Only checks isAuthenticated, not role — any logged-in user can create artifacts (CWE-862, CVSS 6.5, BEST_PRACTICE, Tier 2)
      if (!ctx.isAuthenticated) {
        throw new Error("Not authenticated");
      }

      const artifactRepo = AppDataSource.getRepository(Artifact);
      const artifact = artifactRepo.create({
        ...input,
        catalogedById: ctx.user!.id,
        status: ArtifactStatus.DRAFT,
        auditLog: [
          {
            action: "CREATED",
            userId: ctx.user!.id,
            timestamp: new Date().toISOString(),
          },
        ],
      });

      return artifactRepo.save(artifact);
    },

    // BUG-0091: Update doesn't verify artifact belongs to user or check curator role (CWE-862, CVSS 7.5, HIGH, Tier 1)
    updateArtifact: async (
      _: any,
      { id, input }: { id: string; input: any },
      ctx: AuthContext
    ) => {
      if (!ctx.isAuthenticated) {
        throw new Error("Not authenticated");
      }

      const artifactRepo = AppDataSource.getRepository(Artifact);
      const artifact = await artifactRepo.findOne({ where: { id } });

      if (!artifact) throw new Error("Artifact not found");

      // BUG-0067 manifests here: spread operator applies ALL input fields including isDeleted and auditLog
      Object.assign(artifact, input);
      artifact.lastEditedById = ctx.user!.id;

      return artifactRepo.save(artifact);
    },

    deleteArtifact: async (_: any, { id }: { id: string }, ctx: AuthContext) => {
      if (!ctx.isAuthenticated) {
        throw new Error("Not authenticated");
      }

      const artifactRepo = AppDataSource.getRepository(Artifact);
      const artifact = await artifactRepo.findOne({ where: { id } });
      if (!artifact) throw new Error("Artifact not found");

      // Soft delete
      artifact.isDeleted = true;
      artifact.deletedAt = new Date();
      await artifactRepo.save(artifact);

      auditLog("ARTIFACT_DELETED", ctx.user!.id, { artifactId: id });
      return true;
    },

    restoreArtifact: async (_: any, { id }: { id: string }, ctx: AuthContext) => {
      if (!ctx.isAuthenticated) throw new Error("Not authenticated");

      const artifactRepo = AppDataSource.getRepository(Artifact);
      const artifact = await artifactRepo.findOne({ where: { id } });
      if (!artifact) throw new Error("Artifact not found");

      artifact.isDeleted = false;
      artifact.deletedAt = undefined as any;
      return artifactRepo.save(artifact);
    },

    // BUG-0092: Bulk update has no limit on number of IDs — can update entire database in one call (CWE-400, CVSS 6.5, TRICKY, Tier 2)
    bulkUpdateArtifacts: async (
      _: any,
      { ids, input }: { ids: string[]; input: any },
      ctx: AuthContext
    ) => {
      if (!ctx.isAuthenticated) throw new Error("Not authenticated");

      const artifactRepo = AppDataSource.getRepository(Artifact);
      const artifacts = await artifactRepo.findByIds(ids);

      const updated: Artifact[] = [];
      for (const artifact of artifacts) {
        Object.assign(artifact, input);
        artifact.lastEditedById = ctx.user!.id;
        updated.push(await artifactRepo.save(artifact));
      }

      return updated;
    },

    // BUG-0093: XML import uses xml2js without disabling external entity processing (CWE-611, CVSS 8.5, CRITICAL, Tier 1)
    importArtifacts: async (_: any, { data }: { data: string }, ctx: AuthContext) => {
      if (!ctx.isAuthenticated) throw new Error("Not authenticated");

      const artifactRepo = AppDataSource.getRepository(Artifact);
      const imported: Artifact[] = [];

      // Detect if data is XML or JSON
      if (data.trim().startsWith("<")) {
        // XML import — XXE vulnerable
        const parser = new xml2js.Parser({
          explicitArray: false,
          // External entities not disabled
        });

        const result = await parser.parseStringPromise(data);
        const items = Array.isArray(result.artifacts?.artifact)
          ? result.artifacts.artifact
          : [result.artifacts?.artifact].filter(Boolean);

        for (const item of items) {
          const artifact = artifactRepo.create({
            title: item.title,
            description: item.description,
            catalogNumber: item.catalogNumber || `IMP-${Date.now()}`,
            origin: item.origin,
            period: item.period,
            catalogedById: ctx.user!.id,
            status: ArtifactStatus.DRAFT,
          });
          imported.push(await artifactRepo.save(artifact));
        }
      } else {
        // JSON import
        // BUG-0094: JSON.parse without try-catch can crash the server (CWE-754, CVSS 4.3, LOW, Tier 3)
        const items = JSON.parse(data);
        const list = Array.isArray(items) ? items : [items];

        for (const item of list) {
          // BUG-0095: Imported artifact data not sanitized — stored XSS via imported records (CWE-79, CVSS 6.5, HIGH, Tier 2)
          const artifact = artifactRepo.create({
            ...item,
            catalogedById: ctx.user!.id,
            status: ArtifactStatus.DRAFT,
          });
          imported.push(await artifactRepo.save(artifact));
        }
      }

      auditLog("ARTIFACTS_IMPORTED", ctx.user!.id, { count: imported.length });
      return imported;
    },

    // ─── Exhibitions ─────────────────────────────────────
    createExhibition: async (_: any, { input }: { input: any }, ctx: AuthContext) => {
      if (!ctx.isAuthenticated) throw new Error("Not authenticated");

      const exhibitionRepo = AppDataSource.getRepository(Exhibition);
      const exhibition = exhibitionRepo.create({
        ...input,
        createdById: ctx.user!.id,
      });

      return exhibitionRepo.save(exhibition);
    },

    updateExhibition: async (
      _: any,
      { id, input }: { id: string; input: any },
      ctx: AuthContext
    ) => {
      if (!ctx.isAuthenticated) throw new Error("Not authenticated");

      const exhibitionRepo = AppDataSource.getRepository(Exhibition);
      const exhibition = await exhibitionRepo.findOne({ where: { id } });
      if (!exhibition) throw new Error("Exhibition not found");

      // BUG-0068 manifests: currentAttendance can be directly set by client
      Object.assign(exhibition, input);
      return exhibitionRepo.save(exhibition);
    },

    deleteExhibition: async (_: any, { id }: { id: string }, ctx: AuthContext) => {
      if (!ctx.isAuthenticated) throw new Error("Not authenticated");

      const exhibitionRepo = AppDataSource.getRepository(Exhibition);
      // BUG-0096: Hard delete — no soft delete, no referential integrity check for linked artifacts (CWE-404, CVSS 5.3, BEST_PRACTICE, Tier 3)
      await exhibitionRepo.delete(id);

      auditLog("EXHIBITION_DELETED", ctx.user!.id, { exhibitionId: id });
      return true;
    },

    // BUG-0097: Race condition — artifact can be added to exhibition concurrently without locking (CWE-362, CVSS 5.3, TRICKY, Tier 3)
    addArtifactToExhibition: async (
      _: any,
      { exhibitionId, artifactId }: { exhibitionId: string; artifactId: string },
      ctx: AuthContext
    ) => {
      if (!ctx.isAuthenticated) throw new Error("Not authenticated");

      const exhibitionRepo = AppDataSource.getRepository(Exhibition);
      const artifactRepo = AppDataSource.getRepository(Artifact);

      const exhibition = await exhibitionRepo.findOne({
        where: { id: exhibitionId },
        relations: ["artifacts"],
      });
      if (!exhibition) throw new Error("Exhibition not found");

      const artifact = await artifactRepo.findOne({ where: { id: artifactId } });
      if (!artifact) throw new Error("Artifact not found");

      exhibition.artifacts = [...(exhibition.artifacts || []), artifact];
      return exhibitionRepo.save(exhibition);
    },

    removeArtifactFromExhibition: async (
      _: any,
      { exhibitionId, artifactId }: { exhibitionId: string; artifactId: string },
      ctx: AuthContext
    ) => {
      if (!ctx.isAuthenticated) throw new Error("Not authenticated");

      const exhibitionRepo = AppDataSource.getRepository(Exhibition);
      const exhibition = await exhibitionRepo.findOne({
        where: { id: exhibitionId },
        relations: ["artifacts"],
      });
      if (!exhibition) throw new Error("Exhibition not found");

      exhibition.artifacts = (exhibition.artifacts || []).filter(
        (a) => a.id !== artifactId
      );
      return exhibitionRepo.save(exhibition);
    },

    // ─── Admin ───────────────────────────────────────────
    // RH-007: This looks like it allows any user to call updateUserRole, but
    // the role check below correctly restricts it to ADMIN only.
    updateUserRole: async (
      _: any,
      { userId, role }: { userId: string; role: UserRole },
      ctx: AuthContext
    ) => {
      if (!ctx.isAuthenticated || ctx.user?.role !== UserRole.ADMIN) {
        throw new Error("Admin access required");
      }

      const userRepo = AppDataSource.getRepository(User);
      const user = await userRepo.findOne({ where: { id: userId } });
      if (!user) throw new Error("User not found");

      user.role = role;
      await userRepo.save(user);

      auditLog("ROLE_CHANGED", ctx.user!.id, {
        targetUser: userId,
        newRole: role,
      });

      return user;
    },

    deactivateUser: async (_: any, { userId }: { userId: string }, ctx: AuthContext) => {
      if (!ctx.isAuthenticated || ctx.user?.role !== UserRole.ADMIN) {
        throw new Error("Admin access required");
      }

      const userRepo = AppDataSource.getRepository(User);
      const user = await userRepo.findOne({ where: { id: userId } });
      if (!user) throw new Error("User not found");

      // BUG-0098: Deactivated user's existing JWT tokens are not invalidated (CWE-613, CVSS 6.5, TRICKY, Tier 2)
      user.isActive = false;
      await userRepo.save(user);

      auditLog("USER_DEACTIVATED", ctx.user!.id, { targetUser: userId });
      return true;
    },

    generateApiKey: async (_: any, __: any, ctx: AuthContext) => {
      if (!ctx.isAuthenticated) throw new Error("Not authenticated");

      const userRepo = AppDataSource.getRepository(User);
      // BUG-0027 manifests here: insecure API key generation
      const apiKey = generateApiKey();
      ctx.user!.apiKey = apiKey;
      await userRepo.save(ctx.user!);

      auditLog("API_KEY_GENERATED", ctx.user!.id, {});
      return apiKey;
    },

    purgeDeletedArtifacts: async (_: any, __: any, ctx: AuthContext) => {
      if (!ctx.isAuthenticated) throw new Error("Not authenticated");

      // BUG-0099: Purge operation available to any authenticated user, not just admin (CWE-862, CVSS 7.5, HIGH, Tier 1)
      const artifactRepo = AppDataSource.getRepository(Artifact);
      const deleted = await artifactRepo.find({ where: { isDeleted: true } });
      await artifactRepo.remove(deleted);

      auditLog("ARTIFACTS_PURGED", ctx.user!.id, { count: deleted.length });
      return deleted.length;
    },

    uploadArtifactImage: async (
      _: any,
      { artifactId, url }: { artifactId: string; url: string },
      ctx: AuthContext
    ) => {
      if (!ctx.isAuthenticated) throw new Error("Not authenticated");

      const artifactRepo = AppDataSource.getRepository(Artifact);
      const artifact = await artifactRepo.findOne({ where: { id: artifactId } });
      if (!artifact) throw new Error("Artifact not found");

      // BUG-0100: SSRF — server fetches arbitrary URL provided by user without validation (CWE-918, CVSS 8.5, CRITICAL, Tier 1)
      const fetch = require("node-fetch");
      const response = await fetch(url);
      const buffer = await response.buffer();

      // Store in database as base64 (simplified)
      const base64 = buffer.toString("base64");
      artifact.imageUrls = [...(artifact.imageUrls || []), `data:image/png;base64,${base64}`];
      return artifactRepo.save(artifact);
    },
  },
};

export default mutationResolvers;
