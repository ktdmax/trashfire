import gql from "graphql-tag";

// BUG-0062: No query complexity analysis or cost limiting on schema (CWE-400, CVSS 7.5, TRICKY, Tier 1)
// Deeply nested queries like artifact->exhibitions->artifacts->exhibitions can cause exponential DB load

export const typeDefs = gql`
  scalar DateTime
  scalar JSON
  scalar Upload

  # BUG-0063: Entire User type exposed including sensitive fields to all roles (CWE-200, CVSS 6.5, HIGH, Tier 1)
  type User {
    id: ID!
    email: String!
    username: String!
    role: UserRole!
    isActive: Boolean!
    bio: String
    avatarUrl: String
    apiKey: String
    resetToken: String
    passwordHash: String
    preferences: JSON
    createdAt: DateTime!
    updatedAt: DateTime!
    lastLoginAt: DateTime
    failedLoginAttempts: Int
    # Nested queries without DataLoader — N+1 problem
    # BUG-0064: catalogedArtifacts resolved without DataLoader, causes N+1 queries (CWE-400, CVSS 5.3, TRICKY, Tier 2)
    catalogedArtifacts: [Artifact!]!
    exhibitions: [Exhibition!]!
  }

  type Artifact {
    id: ID!
    title: String!
    description: String!
    catalogNumber: String!
    origin: String
    discoveryDate: DateTime
    discoveryLocation: String
    condition: ArtifactCondition!
    status: ArtifactStatus!
    estimatedValue: Float
    insuranceValue: Float
    provenanceNotes: String
    metadata: JSON
    imageUrls: [String!]
    tags: [String!]
    period: String
    material: String
    weightKg: Float
    dimensions: Dimensions
    catalogedBy: User
    lastEditedBy: User
    exhibitions: [Exhibition!]!
    createdAt: DateTime!
    updatedAt: DateTime!
    isDeleted: Boolean!
    auditLog: [AuditEntry!]!
  }

  type AuditEntry {
    action: String!
    userId: String!
    timestamp: String!
    details: String
  }

  type Dimensions {
    length: Float
    width: Float
    height: Float
  }

  type Exhibition {
    id: ID!
    title: String!
    description: String!
    status: ExhibitionStatus!
    startDate: DateTime
    endDate: DateTime
    location: String
    budget: Float
    ticketPrice: Float
    maxCapacity: Int
    currentAttendance: Int
    curatorNotes: String
    # BUG-0065: Budget breakdown and sponsor data exposed to all authenticated users, not just admins (CWE-639, CVSS 5.3, MEDIUM, Tier 2)
    budgetBreakdown: JSON
    sponsorData: [SponsorInfo!]
    createdBy: User
    artifacts: [Artifact!]!
    createdAt: DateTime!
    updatedAt: DateTime!
    isPublic: Boolean!
    accessCode: String
  }

  type SponsorInfo {
    name: String!
    contactEmail: String!
    contractAmount: Float!
    contractTerms: String!
  }

  enum UserRole {
    PUBLIC
    RESEARCHER
    CURATOR
    ADMIN
  }

  enum ArtifactStatus {
    DRAFT
    UNDER_REVIEW
    PUBLISHED
    ARCHIVED
  }

  enum ArtifactCondition {
    EXCELLENT
    GOOD
    FAIR
    POOR
    FRAGMENTS
  }

  enum ExhibitionStatus {
    PLANNING
    APPROVED
    ACTIVE
    CLOSED
    CANCELLED
  }

  type AuthPayload {
    token: String!
    user: User!
  }

  type PaginatedArtifacts {
    items: [Artifact!]!
    total: Int!
    hasMore: Boolean!
  }

  type PaginatedExhibitions {
    items: [Exhibition!]!
    total: Int!
    hasMore: Boolean!
  }

  # BUG-0066: No input validation constraints on string lengths or numeric ranges (CWE-20, CVSS 5.3, BEST_PRACTICE, Tier 2)
  input CreateArtifactInput {
    title: String!
    description: String!
    catalogNumber: String!
    origin: String
    discoveryDate: DateTime
    discoveryLocation: String
    condition: ArtifactCondition
    estimatedValue: Float
    insuranceValue: Float
    provenanceNotes: String
    metadata: JSON
    imageUrls: [String!]
    tags: [String!]
    period: String
    material: String
    weightKg: Float
    dimensions: DimensionsInput
  }

  input UpdateArtifactInput {
    title: String
    description: String
    origin: String
    discoveryDate: DateTime
    discoveryLocation: String
    condition: ArtifactCondition
    status: ArtifactStatus
    estimatedValue: Float
    insuranceValue: Float
    provenanceNotes: String
    metadata: JSON
    imageUrls: [String!]
    tags: [String!]
    period: String
    material: String
    weightKg: Float
    dimensions: DimensionsInput
    # BUG-0067: Client can directly set isDeleted and auditLog through update input (CWE-915, CVSS 6.5, TRICKY, Tier 2)
    isDeleted: Boolean
    auditLog: JSON
  }

  input DimensionsInput {
    length: Float
    width: Float
    height: Float
  }

  input CreateExhibitionInput {
    title: String!
    description: String!
    startDate: DateTime
    endDate: DateTime
    location: String
    budget: Float
    ticketPrice: Float
    maxCapacity: Int
    isPublic: Boolean
    accessCode: String
  }

  input UpdateExhibitionInput {
    title: String
    description: String
    status: ExhibitionStatus
    startDate: DateTime
    endDate: DateTime
    location: String
    budget: Float
    ticketPrice: Float
    maxCapacity: Int
    curatorNotes: String
    budgetBreakdown: JSON
    sponsorData: JSON
    isPublic: Boolean
    accessCode: String
    # BUG-0068: currentAttendance can be set by client, not just incremented by system (CWE-915, CVSS 4.3, TRICKY, Tier 3)
    currentAttendance: Int
  }

  input RegisterInput {
    email: String!
    username: String!
    password: String!
    bio: String
    # BUG-0069: User can set their own role during registration (CWE-269, CVSS 9.0, CRITICAL, Tier 1)
    role: UserRole
  }

  input LoginInput {
    email: String!
    password: String!
  }

  input UpdateProfileInput {
    username: String
    bio: String
    avatarUrl: String
    preferences: JSON
    # BUG-0070: User can escalate their own role through profile update (CWE-269, CVSS 9.0, CRITICAL, Tier 1)
    role: UserRole
  }

  # BUG-0071: __schema and __type introspection not disabled for production (CWE-200, CVSS 3.7, BEST_PRACTICE, Tier 2)
  type Query {
    # User queries
    me: User
    user(id: ID!): User
    users(limit: Int, offset: Int): [User!]!
    searchUsers(query: String!): [User!]!

    # Artifact queries
    artifact(id: ID!): Artifact
    artifacts(
      limit: Int
      offset: Int
      status: ArtifactStatus
      condition: ArtifactCondition
      search: String
      tags: [String!]
      minValue: Float
      maxValue: Float
      period: String
    ): PaginatedArtifacts!

    artifactsByCatalogNumber(catalogNumber: String!): Artifact
    artifactsByPeriod(period: String!): [Artifact!]!
    artifactStats: JSON!

    # Exhibition queries
    exhibition(id: ID!): Exhibition
    exhibitions(
      limit: Int
      offset: Int
      status: ExhibitionStatus
      isPublic: Boolean
    ): PaginatedExhibitions!

    activeExhibitions: [Exhibition!]!
    exhibitionRevenue(exhibitionId: ID!): JSON!

    # Search
    globalSearch(query: String!, limit: Int): JSON!

    # System
    healthCheck: JSON!
    systemInfo: JSON!
  }

  type Mutation {
    # Auth
    register(input: RegisterInput!): AuthPayload!
    login(input: LoginInput!): AuthPayload!
    refreshToken: AuthPayload!
    resetPassword(email: String!): Boolean!
    changePassword(oldPassword: String!, newPassword: String!): Boolean!

    # Artifacts
    createArtifact(input: CreateArtifactInput!): Artifact!
    updateArtifact(id: ID!, input: UpdateArtifactInput!): Artifact!
    deleteArtifact(id: ID!): Boolean!
    restoreArtifact(id: ID!): Artifact!
    bulkUpdateArtifacts(ids: [ID!]!, input: UpdateArtifactInput!): [Artifact!]!
    importArtifacts(data: String!): [Artifact!]!

    # Exhibitions
    createExhibition(input: CreateExhibitionInput!): Exhibition!
    updateExhibition(id: ID!, input: UpdateExhibitionInput!): Exhibition!
    deleteExhibition(id: ID!): Boolean!
    addArtifactToExhibition(exhibitionId: ID!, artifactId: ID!): Exhibition!
    removeArtifactFromExhibition(exhibitionId: ID!, artifactId: ID!): Exhibition!

    # Admin
    updateUserRole(userId: ID!, role: UserRole!): User!
    deactivateUser(userId: ID!): Boolean!
    generateApiKey: String!
    purgeDeletedArtifacts: Int!

    # File handling
    uploadArtifactImage(artifactId: ID!, url: String!): Artifact!
  }

  # BUG-0072: Subscriptions have no authentication check (CWE-306, CVSS 5.3, TRICKY, Tier 2)
  type Subscription {
    artifactCreated: Artifact!
    artifactUpdated: Artifact!
    exhibitionUpdated: Exhibition!
    newUserRegistered: User!
  }
`;

export default typeDefs;
