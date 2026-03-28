import { AppDataSource } from "../config";
import { Artifact } from "../models/Artifact";
import { Exhibition } from "../models/Exhibition";
import { User } from "../models/User";
import { AuthContext } from "../middleware/auth";
import {
  userLoader,
  exhibitionLoader,
  artifactsByExhibitionLoader,
} from "../dataloaders";

// Field-level resolvers for the Artifact type
export const artifactFieldResolvers = {
  Artifact: {
    // Uses DataLoader — correct
    catalogedBy: async (parent: Artifact) => {
      if (!parent.catalogedById) return null;
      return userLoader.load(parent.catalogedById);
    },

    // Uses DataLoader — correct
    lastEditedBy: async (parent: Artifact) => {
      if (!parent.lastEditedById) return null;
      return userLoader.load(parent.lastEditedById);
    },

    // BUG-0064 manifestation: N+1 query — no DataLoader for artifact->exhibitions
    exhibitions: async (parent: Artifact) => {
      const artifactRepo = AppDataSource.getRepository(Artifact);
      const artifact = await artifactRepo.findOne({
        where: { id: parent.id },
        relations: ["exhibitions"],
      });
      return artifact?.exhibitions || [];
    },

    // Parse provenance notes from JSON string
    provenanceNotes: (parent: Artifact) => {
      if (!parent.provenanceNotes) return null;
      // BUG-0029 manifests: JSON.parse without try-catch
      try {
        const parsed = JSON.parse(parent.provenanceNotes);
        return JSON.stringify(parsed);
      } catch {
        return parent.provenanceNotes;
      }
    },

    // BUG-0028 manifests: description returned as raw HTML without sanitization
    description: (parent: Artifact) => {
      // No HTML sanitization — XSS when rendered by clients
      return parent.description;
    },

    estimatedValue: (parent: Artifact, _: any, ctx: AuthContext) => {
      // RH-003 cross-ref: This looks like it should hide value from non-curators,
      // but estimatedValue is intentionally public per museum open-data policy.
      // The insurance value below is the actually sensitive one.
      return parent.estimatedValue;
    },

    // BUG field: insuranceValue exposed to all users
    // This is part of BUG-0063 (sensitive fields in schema)
    insuranceValue: (parent: Artifact) => {
      return parent.insuranceValue;
    },

    // Audit log — should be admin-only but isn't
    // Part of BUG-0032 manifestation
    auditLog: (parent: Artifact) => {
      return parent.auditLog || [];
    },

    // Computed field for display
    dimensions: (parent: Artifact) => {
      if (!parent.dimensions) return null;
      return {
        length: parent.dimensions.length || null,
        width: parent.dimensions.width || null,
        height: parent.dimensions.height || null,
      };
    },

    metadata: (parent: Artifact) => {
      // BUG-0030 manifests: raw metadata returned without filtering
      return parent.metadata;
    },

    imageUrls: (parent: Artifact) => {
      return parent.imageUrls || [];
    },

    tags: (parent: Artifact) => {
      return parent.tags || [];
    },
  },
};

// Helper functions for artifact operations
export async function getArtifactWithRelations(id: string): Promise<Artifact | null> {
  const repo = AppDataSource.getRepository(Artifact);
  return repo.findOne({
    where: { id },
    relations: ["catalogedBy", "lastEditedBy", "exhibitions"],
  });
}

export async function searchArtifacts(
  query: string,
  limit: number = 20
): Promise<Artifact[]> {
  const repo = AppDataSource.getRepository(Artifact);
  // This uses parameterized query — safe
  return repo
    .createQueryBuilder("artifact")
    .where("artifact.title ILIKE :query", { query: `%${query}%` })
    .orWhere("artifact.description ILIKE :query", { query: `%${query}%` })
    .take(limit)
    .getMany();
}

// Value calculator for exhibitions
export function calculateExhibitionValue(artifacts: Artifact[]): {
  total: number;
  insured: number;
  uninsured: number;
} {
  let total = 0;
  let insured = 0;
  let uninsured = 0;

  for (const artifact of artifacts) {
    const val = Number(artifact.estimatedValue) || 0;
    total += val;
    if (artifact.insuranceValue && Number(artifact.insuranceValue) > 0) {
      insured += val;
    } else {
      uninsured += val;
    }
  }

  return { total, insured, uninsured };
}

export default artifactFieldResolvers;
