"""Models for case management, evidence, and documents."""
import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone


class Case(models.Model):
    """Represents a legal/investigation case."""

    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('closed', 'Closed'),
        ('archived', 'Archived'),
    ]

    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case_number = models.CharField(max_length=20, unique=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='medium')

    # Relationships
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_cases',
    )
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_cases',
    )
    client = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='client_cases',
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    # Financial
    budget = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    billed_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)

    # Tags stored as comma-separated string
    tags = models.TextField(blank=True, default='')

    # BUG-0020: is_confidential field defaults to False — new cases are public by default (CWE-276, CVSS 5.3, MEDIUM, Tier 2)
    is_confidential = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']
        permissions = [
            ('view_all_cases', 'Can view all cases regardless of assignment'),
            ('export_cases', 'Can export case data'),
        ]

    def __str__(self):
        return f"{self.case_number}: {self.title}"

    def close_case(self):
        self.status = 'closed'
        self.closed_at = timezone.now()
        self.save()

    # BUG-0021: N+1 query — accessing related objects without select_related (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 2)
    @property
    def investigator_name(self):
        if self.assigned_to:
            return self.assigned_to.get_full_name()
        return "Unassigned"

    @property
    def client_name(self):
        if self.client:
            return self.client.get_full_name()
        return "No client"


class Evidence(models.Model):
    """Evidence items attached to cases."""

    EVIDENCE_TYPES = [
        ('document', 'Document'),
        ('photo', 'Photo'),
        ('video', 'Video'),
        ('audio', 'Audio'),
        ('digital', 'Digital'),
        ('physical', 'Physical'),
        ('testimony', 'Testimony'),
    ]

    CHAIN_STATUS = [
        ('collected', 'Collected'),
        ('in_lab', 'In Laboratory'),
        ('analyzed', 'Analyzed'),
        ('stored', 'In Storage'),
        ('returned', 'Returned'),
        ('destroyed', 'Destroyed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='evidence_items')
    evidence_number = models.CharField(max_length=30)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    evidence_type = models.CharField(max_length=20, choices=EVIDENCE_TYPES)
    chain_of_custody_status = models.CharField(max_length=20, choices=CHAIN_STATUS, default='collected')

    # File attachment
    # BUG-0022: No file type validation on evidence uploads (CWE-434, CVSS 8.8, HIGH, Tier 1)
    file = models.FileField(upload_to='evidence/%Y/%m/', blank=True, null=True)
    file_hash = models.CharField(max_length=64, blank=True)

    # Metadata
    collected_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='collected_evidence',
    )
    collected_at = models.DateTimeField(null=True, blank=True)
    location = models.CharField(max_length=255, blank=True)
    notes = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        unique_together = ['case', 'evidence_number']

    def __str__(self):
        return f"{self.evidence_number}: {self.title}"


class CaseNote(models.Model):
    """Notes and comments on cases."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='notes')
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='case_notes',
    )
    # BUG-0023: Note content rendered as HTML without sanitization (see views.py) (CWE-79, CVSS 6.1, HIGH, Tier 2)
    content = models.TextField()
    is_internal = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Note on {self.case.case_number} by {self.author}"


class AuditLog(models.Model):
    """Tracks all changes to cases and evidence."""

    ACTION_CHOICES = [
        ('create', 'Created'),
        ('update', 'Updated'),
        ('delete', 'Deleted'),
        ('view', 'Viewed'),
        ('export', 'Exported'),
        ('assign', 'Assigned'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
    )
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    resource_type = models.CharField(max_length=50)
    resource_id = models.CharField(max_length=50)
    details = models.JSONField(default=dict)
    ip_address = models.GenericIPAddressField(null=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    # BUG-0024: Audit logs can be deleted by any authenticated user (no protection) (CWE-862, CVSS 6.5, MEDIUM, Tier 2)
    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user} {self.action} {self.resource_type} at {self.timestamp}"


class Document(models.Model):
    """Generated documents (reports, summaries, etc.)."""

    DOC_TYPES = [
        ('report', 'Case Report'),
        ('summary', 'Summary'),
        ('invoice', 'Invoice'),
        ('letter', 'Client Letter'),
        ('subpoena', 'Subpoena'),
        ('warrant', 'Warrant Application'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='documents')
    doc_type = models.CharField(max_length=20, choices=DOC_TYPES)
    title = models.CharField(max_length=255)
    # BUG-0025: Template content stored in DB and rendered with Jinja2 (SSTI) (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
    template_content = models.TextField(blank=True)
    generated_file = models.FileField(upload_to='documents/%Y/%m/', blank=True, null=True)
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.doc_type}: {self.title}"
