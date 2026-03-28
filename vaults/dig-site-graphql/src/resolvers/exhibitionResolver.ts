import { AppDataSource } from "../config";
import { Exhibition, ExhibitionStatus } from "../models/Exhibition";
import { Artifact } from "../models/Artifact";
import { User, UserRole } from "../models/User";
import { AuthContext } from "../middleware/auth";
import { userLoader, artifactsByExhibitionLoader } from "../dataloaders";

// Field-level resolvers for the Exhibition type
export const exhibitionFieldResolvers = {
  Exhibition: {
    createdBy: async (parent: Exhibition) => {
      if (!parent.createdById) return null;
      return userLoader.load(parent.createdById);
    },

    // Uses DataLoader for artifacts — correct for batch loading
    artifacts: async (parent: Exhibition) => {
      if (parent.artifacts && parent.artifacts.length > 0) {
        return parent.artifacts;
      }
      return artifactsByExhibitionLoader.load(parent.id);
    },

    // BUG-0065 manifestation: budgetBreakdown accessible without role check
    budgetBreakdown: (parent: Exhibition, _: any, ctx: AuthContext) => {
      // Should check for ADMIN or CURATOR role, but doesn't
      return parent.budgetBreakdown;
    },

    // BUG-0035 manifestation: sponsorData exposed including contract terms
    sponsorData: (parent: Exhibition, _: any, ctx: AuthContext) => {
      return parent.sponsorData || [];
    },

    // BUG-0034 manifestation: curatorNotes visible to all
    curatorNotes: (parent: Exhibition, _: any, ctx: AuthContext) => {
      return parent.curatorNotes;
    },

    // BUG-0036 manifestation: accessCode for private exhibitions exposed in queries
    accessCode: (parent: Exhibition) => {
      // Should be hidden from non-admin users
      return parent.accessCode;
    },

    // Computed fields
    description: (parent: Exhibition) => {
      // BUG-0033 manifestation: raw HTML returned
      return parent.description;
    },

    // Revenue computation
    ticketPrice: (parent: Exhibition) => {
      return parent.ticketPrice || 0;
    },

    currentAttendance: (parent: Exhibition) => {
      return parent.currentAttendance || 0;
    },

    // Status with date-based logic
    status: (parent: Exhibition) => {
      // Auto-close past exhibitions
      if (
        parent.status === ExhibitionStatus.ACTIVE &&
        parent.endDate &&
        new Date(parent.endDate) < new Date()
      ) {
        // Note: this doesn't persist the change — just a display-level override
        return ExhibitionStatus.CLOSED;
      }
      return parent.status;
    },
  },
};

// Exhibition analytics helper
export async function getExhibitionAnalytics(exhibitionId: string): Promise<any> {
  const repo = AppDataSource.getRepository(Exhibition);
  const exhibition = await repo.findOne({
    where: { id: exhibitionId },
    relations: ["artifacts"],
  });

  if (!exhibition) return null;

  const artifacts = exhibition.artifacts || [];
  const totalValue = artifacts.reduce(
    (sum, a) => sum + (Number(a.estimatedValue) || 0),
    0
  );

  const conditions: Record<string, number> = {};
  for (const artifact of artifacts) {
    conditions[artifact.condition] = (conditions[artifact.condition] || 0) + 1;
  }

  const periods: Record<string, number> = {};
  for (const artifact of artifacts) {
    if (artifact.period) {
      periods[artifact.period] = (periods[artifact.period] || 0) + 1;
    }
  }

  return {
    exhibitionId,
    artifactCount: artifacts.length,
    totalEstimatedValue: totalValue,
    conditionBreakdown: conditions,
    periodBreakdown: periods,
    revenue: (exhibition.ticketPrice || 0) * (exhibition.currentAttendance || 0),
    capacity: exhibition.maxCapacity,
    utilizationPercent: exhibition.maxCapacity
      ? ((exhibition.currentAttendance || 0) / exhibition.maxCapacity) * 100
      : 0,
  };
}

// Date overlap checker for exhibitions at same location
export async function checkScheduleConflict(
  location: string,
  startDate: Date,
  endDate: Date,
  excludeId?: string
): Promise<Exhibition[]> {
  const repo = AppDataSource.getRepository(Exhibition);
  const qb = repo
    .createQueryBuilder("e")
    .where("e.location = :location", { location })
    .andWhere("e.startDate <= :endDate", { endDate })
    .andWhere("e.endDate >= :startDate", { startDate })
    .andWhere("e.status NOT IN (:...excluded)", {
      excluded: [ExhibitionStatus.CANCELLED, ExhibitionStatus.CLOSED],
    });

  if (excludeId) {
    qb.andWhere("e.id != :excludeId", { excludeId });
  }

  return qb.getMany();
}

// Attendance tracking helper
export async function recordAttendance(
  exhibitionId: string,
  count: number = 1
): Promise<Exhibition | null> {
  const repo = AppDataSource.getRepository(Exhibition);
  const exhibition = await repo.findOne({ where: { id: exhibitionId } });

  if (!exhibition) return null;
  if (exhibition.status !== ExhibitionStatus.ACTIVE) return null;

  exhibition.currentAttendance = (exhibition.currentAttendance || 0) + count;
  return repo.save(exhibition);
}

export default exhibitionFieldResolvers;
