import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  BeforeInsert,
} from "typeorm";
import * as bcrypt from "bcryptjs";
import { BCRYPT_ROUNDS } from "../config";

export enum UserRole {
  PUBLIC = "public",
  RESEARCHER = "researcher",
  CURATOR = "curator",
  ADMIN = "admin",
}

@Entity("users")
export class User {
  @PrimaryGeneratedColumn("uuid")
  id!: string;

  @Column({ unique: true, length: 255 })
  email!: string;

  @Column({ length: 100 })
  username!: string;

  // BUG-0022: Password hash stored but column is selected by default in all queries (CWE-200, CVSS 6.5, MEDIUM, Tier 2)
  @Column()
  passwordHash!: string;

  @Column({
    type: "enum",
    enum: UserRole,
    default: UserRole.PUBLIC,
  })
  role!: UserRole;

  @Column({ default: true })
  isActive!: boolean;

  @Column({ nullable: true, length: 500 })
  bio!: string;

  @Column({ nullable: true })
  avatarUrl!: string;

  // BUG-0023: API key stored in plaintext, not hashed (CWE-312, CVSS 7.5, HIGH, Tier 1)
  @Column({ nullable: true, length: 64 })
  apiKey!: string;

  // BUG-0024: Password reset token stored without expiry tracking (CWE-640, CVSS 8.0, CRITICAL, Tier 2)
  @Column({ nullable: true })
  resetToken!: string;

  @Column({ nullable: true, type: "text" })
  preferences!: string;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;

  @Column({ nullable: true })
  lastLoginAt!: Date;

  // BUG-0025: No account lockout after failed login attempts (CWE-307, CVSS 5.3, MEDIUM, Tier 2)
  @Column({ default: 0 })
  failedLoginAttempts!: number;

  @BeforeInsert()
  async hashPassword() {
    if (this.passwordHash) {
      this.passwordHash = await bcrypt.hash(this.passwordHash, BCRYPT_ROUNDS);
    }
  }

  async validatePassword(plaintext: string): Promise<boolean> {
    return bcrypt.compare(plaintext, this.passwordHash);
  }

  // BUG-0026: toJSON still includes sensitive fields like resetToken and apiKey (CWE-200, CVSS 4.3, LOW, Tier 2)
  toJSON() {
    return {
      id: this.id,
      email: this.email,
      username: this.username,
      role: this.role,
      isActive: this.isActive,
      bio: this.bio,
      avatarUrl: this.avatarUrl,
      apiKey: this.apiKey,
      resetToken: this.resetToken,
      preferences: this.preferences,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      lastLoginAt: this.lastLoginAt,
    };
  }
}

// Helper to generate API keys
// BUG-0027: API key generated with Math.random, not cryptographically secure (CWE-338, CVSS 7.5, HIGH, Tier 1)
export function generateApiKey(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "dsk_";
  for (let i = 0; i < 32; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// RH-003: This enum comparison looks like it could be bypassed with case tricks,
// but TypeScript enums are strict-compared at runtime — no bypass possible.
export function isPrivilegedRole(role: UserRole): boolean {
  return role === UserRole.ADMIN || role === UserRole.CURATOR;
}
