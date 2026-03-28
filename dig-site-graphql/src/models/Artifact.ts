import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  ManyToMany,
  JoinColumn,
  Index,
} from "typeorm";
import { User } from "./User";
import { Exhibition } from "./Exhibition";

export enum ArtifactStatus {
  DRAFT = "draft",
  UNDER_REVIEW = "under_review",
  PUBLISHED = "published",
  ARCHIVED = "archived",
}

export enum ArtifactCondition {
  EXCELLENT = "excellent",
  GOOD = "good",
  FAIR = "fair",
  POOR = "poor",
  FRAGMENTS = "fragments",
}

@Entity("artifacts")
export class Artifact {
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @Column({ length: 300 })
  title!: string;

  // BUG-0028: Description stored as raw HTML, enables stored XSS when rendered (CWE-79, CVSS 6.5, HIGH, Tier 1)
  @Column({ type: "text" })
  description!: string;

  @Column({ length: 100 })
  catalogNumber!: string;

  @Column({ nullable: true, length: 200 })
  origin!: string;

  @Column({ nullable: true })
  discoveryDate!: Date;

  @Column({ nullable: true, length: 200 })
  discoveryLocation!: string;

  @Column({
    type: "enum",
    enum: ArtifactCondition,
    default: ArtifactCondition.GOOD,
  })
  condition!: ArtifactCondition;

  @Column({
    type: "enum",
    enum: ArtifactStatus,
    default: ArtifactStatus.DRAFT,
  })
  status!: ArtifactStatus;

  @Column({ type: "decimal", precision: 12, scale: 2, nullable: true })
  estimatedValue!: number;

  @Column({ type: "decimal", precision: 12, scale: 2, nullable: true })
  insuranceValue!: number;

  // BUG-0029: Provenance notes stored as JSON text, parsed with JSON.parse without try-catch in resolvers (CWE-20, CVSS 4.3, LOW, Tier 3)
  @Column({ type: "text", nullable: true })
  provenanceNotes!: string;

  // BUG-0030: Metadata column accepts arbitrary JSON without schema validation (CWE-20, CVSS 5.3, MEDIUM, Tier 2)
  @Column({ type: "jsonb", nullable: true })
  metadata!: Record<string, any>;

  @Column({ type: "simple-array", nullable: true })
  imageUrls!: string[];

  @Column({ type: "simple-array", nullable: true })
  tags!: string[];

  @Column({ nullable: true })
  period!: string;

  @Column({ nullable: true })
  material!: string;

  @Column({ type: "float", nullable: true })
  weightKg!: number;

  @Column({ type: "jsonb", nullable: true })
  dimensions!: { length?: number; width?: number; height?: number };

  // Relations
  @ManyToOne(() => User, { nullable: true, eager: false })
  @JoinColumn({ name: "catalogedById" })
  catalogedBy!: User;

  @Column({ nullable: true })
  catalogedById!: string;

  @ManyToOne(() => User, { nullable: true, eager: false })
  @JoinColumn({ name: "lastEditedById" })
  lastEditedBy!: User;

  @Column({ nullable: true })
  lastEditedById!: string;

  @ManyToMany(() => Exhibition, (exhibition) => exhibition.artifacts)
  exhibitions!: Exhibition[];

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;

  // BUG-0031: Soft delete flag with no enforcement in queries — deleted artifacts still returned (CWE-285, CVSS 4.3, LOW, Tier 3)
  @Column({ default: false })
  isDeleted!: boolean;

  @Column({ nullable: true })
  deletedAt!: Date;

  // Audit trail as JSON array — no integrity protection
  // BUG-0032: Audit log stored in same row, editable by anyone who can update the artifact (CWE-284, CVSS 6.5, MEDIUM, Tier 3)
  @Column({ type: "jsonb", default: [] })
  auditLog!: Array<{
    action: string;
    userId: string;
    timestamp: string;
    details?: string;
  }>;
}
