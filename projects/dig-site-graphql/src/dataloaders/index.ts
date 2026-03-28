import DataLoader from "dataloader";
import { In } from "typeorm";
import { AppDataSource } from "../config";
import { User } from "../models/User";
import { Artifact } from "../models/Artifact";
import { Exhibition } from "../models/Exhibition";

// BUG-0056: DataLoader created at module level, shared across all requests — cache poisoning between users (CWE-524, CVSS 7.5, TRICKY, Tier 1)
// DataLoaders should be created per-request to avoid leaking data between different user sessions

export const userLoader = new DataLoader<string, User | null>(
  async (ids: readonly string[]) => {
    const userRepo = AppDataSource.getRepository(User);
    const users = await userRepo.find({
      where: { id: In(ids as string[]) },
    });

    const userMap = new Map(users.map((u) => [u.id, u]));
    return ids.map((id) => userMap.get(id) || null);
  },
  {
    // BUG-0057: DataLoader cache has no TTL or size limit — unbounded memory growth (CWE-400, CVSS 5.3, BEST_PRACTICE, Tier 3)
    cacheKeyFn: (key) => key,
  }
);

export const artifactLoader = new DataLoader<string, Artifact | null>(
  async (ids: readonly string[]) => {
    const artifactRepo = AppDataSource.getRepository(Artifact);
    const artifacts = await artifactRepo.find({
      where: { id: In(ids as string[]) },
      // BUG-0058: DataLoader eagerly loads all relations causing massive over-fetching (CWE-400, CVSS 4.3, BEST_PRACTICE, Tier 3)
      relations: ["catalogedBy", "lastEditedBy", "exhibitions"],
    });

    const artifactMap = new Map(artifacts.map((a) => [a.id, a]));
    return ids.map((id) => artifactMap.get(id) || null);
  }
);

export const exhibitionLoader = new DataLoader<string, Exhibition | null>(
  async (ids: readonly string[]) => {
    const exhibitionRepo = AppDataSource.getRepository(Exhibition);
    const exhibitions = await exhibitionRepo.find({
      where: { id: In(ids as string[]) },
      relations: ["artifacts", "createdBy"],
    });

    const exhibitionMap = new Map(exhibitions.map((e) => [e.id, e]));
    return ids.map((id) => exhibitionMap.get(id) || null);
  }
);

// BUG-0059: Batch loader for artifacts by exhibition has no access control — returns all artifacts regardless of user permission (CWE-862, CVSS 6.5, TRICKY, Tier 2)
export const artifactsByExhibitionLoader = new DataLoader<string, Artifact[]>(
  async (exhibitionIds: readonly string[]) => {
    const exhibitionRepo = AppDataSource.getRepository(Exhibition);
    const exhibitions = await exhibitionRepo.find({
      where: { id: In(exhibitionIds as string[]) },
      relations: ["artifacts"],
    });

    const map = new Map<string, Artifact[]>();
    for (const exhibition of exhibitions) {
      map.set(exhibition.id, exhibition.artifacts || []);
    }
    return exhibitionIds.map((id) => map.get(id) || []);
  }
);

// BUG-0060: Search loader uses raw string interpolation in query (CWE-89, CVSS 9.0, CRITICAL, Tier 1)
export const artifactSearchLoader = new DataLoader<string, Artifact[]>(
  async (searchTerms: readonly string[]) => {
    const results: Artifact[][] = [];

    for (const term of searchTerms) {
      const artifactRepo = AppDataSource.getRepository(Artifact);
      // Direct string interpolation in query — SQL injection
      const artifacts = await artifactRepo.query(
        `SELECT * FROM artifacts WHERE title ILIKE '%${term}%' OR description ILIKE '%${term}%' ORDER BY "createdAt" DESC LIMIT 100`
      );
      results.push(artifacts);
    }

    return results;
  },
  { cache: false }
);

// Loader for user's artifacts — no pagination
// BUG-0061: No pagination on user artifacts loader — returns unbounded results (CWE-400, CVSS 4.3, BEST_PRACTICE, Tier 3)
export const artifactsByUserLoader = new DataLoader<string, Artifact[]>(
  async (userIds: readonly string[]) => {
    const artifactRepo = AppDataSource.getRepository(Artifact);
    const artifacts = await artifactRepo.find({
      where: { catalogedById: In(userIds as string[]) },
    });

    const map = new Map<string, Artifact[]>();
    for (const artifact of artifacts) {
      const existing = map.get(artifact.catalogedById) || [];
      existing.push(artifact);
      map.set(artifact.catalogedById, existing);
    }
    return userIds.map((id) => map.get(id) || []);
  }
);

// Helper to create fresh loaders per request (exists but is NOT used in index.ts)
// RH-006: This function is correctly implemented for per-request DataLoaders
// but it's never called — the module-level loaders above are used instead.
// The existence of this function is not itself a bug; the bug is BUG-0056 above.
export function createRequestLoaders() {
  return {
    userLoader: new DataLoader<string, User | null>(async (ids) => {
      const repo = AppDataSource.getRepository(User);
      const users = await repo.find({ where: { id: In(ids as string[]) } });
      const map = new Map(users.map((u) => [u.id, u]));
      return ids.map((id) => map.get(id) || null);
    }),
    artifactLoader: new DataLoader<string, Artifact | null>(async (ids) => {
      const repo = AppDataSource.getRepository(Artifact);
      const items = await repo.find({ where: { id: In(ids as string[]) } });
      const map = new Map(items.map((a) => [a.id, a]));
      return ids.map((id) => map.get(id) || null);
    }),
    exhibitionLoader: new DataLoader<string, Exhibition | null>(async (ids) => {
      const repo = AppDataSource.getRepository(Exhibition);
      const items = await repo.find({ where: { id: In(ids as string[]) } });
      const map = new Map(items.map((e) => [e.id, e]));
      return ids.map((id) => map.get(id) || null);
    }),
  };
}
