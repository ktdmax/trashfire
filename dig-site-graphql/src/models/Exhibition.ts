import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  ManyToMany,
  JoinTable,
  JoinColumn,
} from "typeorm";
import { User } from "./User";
import { Artifact } from "./Artifact";

export enum ExhibitionStatus {
  PLANNING = "planning",
  APPROVED = "approved",
  ACTIVE = "active",
  CLOSED = "closed",
  CANCELLED = "cancelled",
}

@Entity("exhibitions")
export class Exhibition {
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @Column({ length: 300 })
  title!: string;

  // BUG-0033: Exhibition description also allows raw HTML (CWE-79, CVSS 6.5, HIGH, Tier 1)
  @Column({ type: "text" })
  description!: string;

  @Column({
    type: "enum",
    enum: ExhibitionStatus,
    default: ExhibitionStatus.PLANNING,
  })
  status!: ExhibitionStatus;

  @Column({ nullable: true })
  startDate!: Date;

  @Column({ nullable: true })
  endDate!: Date;

  @Column({ length: 200, nullable: true })
  location!: string;

  @Column({ type: "decimal", precision: 12, scale: 2, nullable: true })
  budget!: number;

  @Column({ type: "decimal", precision: 12, scale: 2, default: 0 })
  ticketPrice!: number;

  @Column({ type: "int", default: 0 })
  maxCapacity!: number;

  @Column({ type: "int", default: 0 })
  currentAttendance!: number;

  @Column({ type: "text", nullable: true })
  curatorNotes!: string;

  // BUG-0034: Internal-only field (budget breakdown) exposed in GraphQL schema without access control (CWE-639, CVSS 5.3, MEDIUM, Tier 2)
  @Column({ type: "jsonb", nullable: true })
  budgetBreakdown!: Record<string, number>;

  // BUG-0035: Sponsor data including contract details stored in queryable JSON (CWE-200, CVSS 4.3, LOW, Tier 2)
  @Column({ type: "jsonb", nullable: true })
  sponsorData!: {
    name: string;
    contactEmail: string;
    contractAmount: number;
    contractTerms: string;
  }[];

  @ManyToOne(() => User, { nullable: true, eager: false })
  @JoinColumn({ name: "createdById" })
  createdBy!: User;

  @Column({ nullable: true })
  createdById!: string;

  @ManyToMany(() => Artifact, (artifact) => artifact.exhibitions)
  @JoinTable({
    name: "exhibition_artifacts",
    joinColumn: { name: "exhibitionId" },
    inverseJoinColumn: { name: "artifactId" },
  })
  artifacts!: Artifact[];

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;

  @Column({ default: false })
  isPublic!: boolean;

  // BUG-0036: Access code for private exhibitions stored in plaintext (CWE-312, CVSS 5.3, MEDIUM, Tier 2)
  @Column({ nullable: true, length: 50 })
  accessCode!: string;
}
