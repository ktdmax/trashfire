import { AppDataSource, MAX_PAGE_SIZE, DEFAULT_PAGE_SIZE } from "../config";
import { Artifact, ArtifactStatus } from "../models/Artifact";
import { Exhibition, ExhibitionStatus } from "../models/Exhibition";
import { User } from "../models/User";
import { AuthContext } from "../middleware/auth";
import { artifactSearchLoader } from "../dataloaders";
import { ILike, In, Between, MoreThanOrEqual, LessThanOrEqual } from "typeorm";

export const queryResolvers = {
  Query: {
    // User queries
    me: async (_: any, __: any, ctx: AuthContext) => {
      if (!ctx.isAuthenticated || !ctx.user) return null;
      return ctx.user;
    },

    // BUG-0073: Any authenticated user can fetch any other user's full profile including sensitive fields (CWE-639, CVSS 6.5, HIGH, Tier 1)
    user: async (_: any, { id }: { id: string }, ctx: AuthContext) => {
      const userRepo = AppDataSource.getRepository(User);
      return userRepo.findOne({ where: { id } });
    },

    // BUG-0074: User listing has no authentication requirement (CWE-306, CVSS 5.3, MEDIUM, Tier 2)
    users: async (_: any, { limit, offset }: { limit?: number; offset?: number }) => {
      const userRepo = AppDataSource.getRepository(User);
      return userRepo.find({
        take: Math.min(limit || DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE),
        skip: offset || 0,
        order: { createdAt: "DESC" },
      });
    },

    // BUG-0075: Search query uses LIKE with user input, potential SQL injection via TypeORM ILike (CWE-89, CVSS 4.3, LOW, Tier 3)
    searchUsers: async (_: any, { query }: { query: string }) => {
      const userRepo = AppDataSource.getRepository(User);
      return userRepo.find({
        where: [
          { username: ILike(`%${query}%`) },
          { email: ILike(`%${query}%`) },
          { bio: ILike(`%${query}%`) },
        ],
        take: 50,
      });
    },

    // Artifact queries
    artifact: async (_: any, { id }: { id: string }, ctx: AuthContext) => {
      const artifactRepo = AppDataSource.getRepository(Artifact);
      // BUG-0076: Deleted artifacts still accessible by direct ID lookup (CWE-285, CVSS 4.3, BEST_PRACTICE, Tier 3)
      return artifactRepo.findOne({ where: { id } });
    },

    artifacts: async (
      _: any,
      args: {
        limit?: number;
        offset?: number;
        status?: ArtifactStatus;
        search?: string;
        tags?: string[];
        minValue?: number;
        maxValue?: number;
        period?: string;
      }
    ) => {
      const artifactRepo = AppDataSource.getRepository(Artifact);
      const take = Math.min(args.limit || DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE);
      const skip = args.offset || 0;

      const where: any = {};

      if (args.status) where.status = args.status;
      if (args.period) where.period = args.period;

      // BUG-0077: Search uses raw DataLoader with SQL injection vulnerability (see BUG-0060) (CWE-89, CVSS 9.0, CRITICAL, Tier 1)
      if (args.search) {
        const searchResults = await artifactSearchLoader.load(args.search);
        return {
          items: searchResults.slice(skip, skip + take),
          total: searchResults.length,
          hasMore: searchResults.length > skip + take,
        };
      }

      const [items, total] = await artifactRepo.findAndCount({
        where,
        take,
        skip,
        order: { createdAt: "DESC" },
      });

      return { items, total, hasMore: total > skip + take };
    },

    artifactsByCatalogNumber: async (_: any, { catalogNumber }: { catalogNumber: string }) => {
      const artifactRepo = AppDataSource.getRepository(Artifact);
      return artifactRepo.findOne({ where: { catalogNumber } });
    },

    artifactsByPeriod: async (_: any, { period }: { period: string }) => {
      const artifactRepo = AppDataSource.getRepository(Artifact);
      return artifactRepo.find({ where: { period } });
    },

    // BUG-0078: Stats query performs expensive aggregation without caching or rate limiting (CWE-400, CVSS 5.3, BEST_PRACTICE, Tier 2)
    artifactStats: async () => {
      const artifactRepo = AppDataSource.getRepository(Artifact);

      const totalCount = await artifactRepo.count();
      const byStatus = await artifactRepo
        .createQueryBuilder("a")
        .select("a.status", "status")
        .addSelect("COUNT(*)", "count")
        .groupBy("a.status")
        .getRawMany();

      const byCondition = await artifactRepo
        .createQueryBuilder("a")
        .select("a.condition", "condition")
        .addSelect("COUNT(*)", "count")
        .groupBy("a.condition")
        .getRawMany();

      const totalValue = await artifactRepo
        .createQueryBuilder("a")
        .select("SUM(a.estimatedValue)", "total")
        .getRawOne();

      return {
        totalCount,
        byStatus,
        byCondition,
        totalEstimatedValue: totalValue?.total || 0,
      };
    },

    // Exhibition queries
    exhibition: async (_: any, { id }: { id: string }, ctx: AuthContext) => {
      const exhibitionRepo = AppDataSource.getRepository(Exhibition);
      const exhibition = await exhibitionRepo.findOne({
        where: { id },
        relations: ["artifacts"],
      });

      // BUG-0079: Private exhibition access code checked with simple equality, no auth required (CWE-285, CVSS 6.5, TRICKY, Tier 2)
      // Anyone can access any exhibition by ID, even private ones
      return exhibition;
    },

    exhibitions: async (
      _: any,
      args: {
        limit?: number;
        offset?: number;
        status?: ExhibitionStatus;
        isPublic?: boolean;
      }
    ) => {
      const exhibitionRepo = AppDataSource.getRepository(Exhibition);
      const take = Math.min(args.limit || DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE);
      const skip = args.offset || 0;

      const where: any = {};
      if (args.status) where.status = args.status;
      if (args.isPublic !== undefined) where.isPublic = args.isPublic;

      const [items, total] = await exhibitionRepo.findAndCount({
        where,
        take,
        skip,
        order: { startDate: "DESC" },
        relations: ["artifacts"],
      });

      return { items, total, hasMore: total > skip + take };
    },

    activeExhibitions: async () => {
      const exhibitionRepo = AppDataSource.getRepository(Exhibition);
      return exhibitionRepo.find({
        where: { status: ExhibitionStatus.ACTIVE },
        relations: ["artifacts"],
      });
    },

    // BUG-0080: Revenue query exposes financial data without admin role check (CWE-862, CVSS 6.5, HIGH, Tier 2)
    exhibitionRevenue: async (_: any, { exhibitionId }: { exhibitionId: string }) => {
      const exhibitionRepo = AppDataSource.getRepository(Exhibition);
      const exhibition = await exhibitionRepo.findOne({ where: { id: exhibitionId } });
      if (!exhibition) throw new Error("Exhibition not found");

      return {
        ticketRevenue: exhibition.ticketPrice * exhibition.currentAttendance,
        budget: exhibition.budget,
        budgetBreakdown: exhibition.budgetBreakdown,
        sponsorTotal: exhibition.sponsorData?.reduce(
          (sum: number, s: any) => sum + (s.contractAmount || 0),
          0
        ),
        sponsorDetails: exhibition.sponsorData,
        netProfit:
          exhibition.ticketPrice * exhibition.currentAttendance -
          (exhibition.budget || 0),
      };
    },

    // BUG-0081: Global search uses raw SQL query with string concatenation (CWE-89, CVSS 9.0, CRITICAL, Tier 1)
    globalSearch: async (_: any, { query, limit }: { query: string; limit?: number }) => {
      const maxResults = limit || 20;
      const artifactRepo = AppDataSource.getRepository(Artifact);
      const exhibitionRepo = AppDataSource.getRepository(Exhibition);
      const userRepo = AppDataSource.getRepository(User);

      // Raw query with string interpolation
      const artifacts = await artifactRepo.query(
        `SELECT id, title, description, "catalogNumber", status FROM artifacts
         WHERE title ILIKE '%${query}%' OR description ILIKE '%${query}%'
         OR "catalogNumber" ILIKE '%${query}%'
         LIMIT ${maxResults}`
      );

      const exhibitions = await exhibitionRepo.query(
        `SELECT id, title, description, status FROM exhibitions
         WHERE title ILIKE '%${query}%' OR description ILIKE '%${query}%'
         LIMIT ${maxResults}`
      );

      const users = await userRepo.query(
        `SELECT id, username, email, role FROM users
         WHERE username ILIKE '%${query}%' OR email ILIKE '%${query}%'
         LIMIT ${maxResults}`
      );

      return { artifacts, exhibitions, users };
    },

    healthCheck: async () => {
      return {
        status: "ok",
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
      };
    },

    // BUG-0082: System info endpoint leaks detailed server configuration (CWE-200, CVSS 5.3, BEST_PRACTICE, Tier 1)
    systemInfo: async () => {
      return {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        memoryUsage: process.memoryUsage(),
        cpuUsage: process.cpuUsage(),
        uptime: process.uptime(),
        env: {
          NODE_ENV: process.env.NODE_ENV,
          DB_HOST: process.env.DB_HOST,
          // BUG-0083: Database credentials exposed through systemInfo query (CWE-200, CVSS 9.0, CRITICAL, Tier 1)
          DB_USER: process.env.DB_USER,
          DB_PASS: process.env.DB_PASS,
          JWT_SECRET: process.env.JWT_SECRET,
          REDIS_URL: process.env.REDIS_URL,
        },
        pid: process.pid,
        cwd: process.cwd(),
      };
    },
  },
};

export default queryResolvers;
