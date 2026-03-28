"""Django admin configuration for case management."""
from django.contrib import admin
from django.utils.safestring import mark_safe

from .models import Case, Evidence, CaseNote, AuditLog, Document


class EvidenceInline(admin.TabularInline):
    model = Evidence
    extra = 0
    fields = ['evidence_number', 'title', 'evidence_type', 'chain_of_custody_status', 'file']
    readonly_fields = ['created_at']


class CaseNoteInline(admin.StackedInline):
    model = CaseNote
    extra = 0
    fields = ['content', 'is_internal', 'author']
    readonly_fields = ['created_at']


@admin.register(Case)
class CaseAdmin(admin.ModelAdmin):
    list_display = [
        'case_number', 'title', 'status', 'priority',
        'assigned_to', 'created_at',
    ]
    list_filter = ['status', 'priority', 'is_confidential', 'created_at']
    search_fields = ['case_number', 'title', 'description']
    inlines = [EvidenceInline, CaseNoteInline]
    readonly_fields = ['created_at', 'updated_at']

    fieldsets = (
        (None, {
            'fields': ('case_number', 'title', 'description', 'status', 'priority'),
        }),
        ('Assignment', {
            'fields': ('created_by', 'assigned_to', 'client'),
        }),
        ('Financial', {
            'fields': ('budget', 'billed_amount'),
        }),
        ('Settings', {
            'fields': ('is_confidential', 'tags'),
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'closed_at'),
            'classes': ('collapse',),
        }),
    )

    # BUG-0065: Admin action to export cases does not check export permission (CWE-862, CVSS 5.3, MEDIUM, Tier 2)
    actions = ['mark_as_closed', 'mark_as_archived', 'export_selected']

    def mark_as_closed(self, request, queryset):
        from django.utils import timezone
        queryset.update(status='closed', closed_at=timezone.now())
        self.message_user(request, f"{queryset.count()} cases marked as closed.")
    mark_as_closed.short_description = "Mark selected cases as closed"

    def mark_as_archived(self, request, queryset):
        queryset.update(status='archived')
        self.message_user(request, f"{queryset.count()} cases archived.")
    mark_as_archived.short_description = "Archive selected cases"

    def export_selected(self, request, queryset):
        """Export selected cases to JSON."""
        import json
        from django.http import HttpResponse

        data = list(queryset.values(
            'case_number', 'title', 'description', 'status',
            'priority', 'budget', 'billed_amount',
        ))
        response = HttpResponse(
            json.dumps(data, indent=2, default=str),
            content_type='application/json',
        )
        response['Content-Disposition'] = 'attachment; filename="cases_export.json"'
        return response
    export_selected.short_description = "Export selected cases to JSON"


@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):
    list_display = [
        'evidence_number', 'title', 'case', 'evidence_type',
        'chain_of_custody_status', 'collected_by', 'created_at',
    ]
    list_filter = ['evidence_type', 'chain_of_custody_status']
    search_fields = ['evidence_number', 'title', 'description']
    readonly_fields = ['created_at', 'updated_at', 'file_hash']

    # BUG-0066: File preview renders HTML from file description — potential stored XSS in admin (CWE-79, CVSS 4.8, MEDIUM, Tier 2)
    def file_preview(self, obj):
        if obj.description:
            return mark_safe(f'<div class="file-preview">{obj.description}</div>')
        return '-'
    file_preview.short_description = 'Preview'


@admin.register(CaseNote)
class CaseNoteAdmin(admin.ModelAdmin):
    list_display = ['case', 'author', 'is_internal', 'created_at']
    list_filter = ['is_internal', 'created_at']
    search_fields = ['content']
    readonly_fields = ['created_at', 'updated_at']

    # RH-004: mark_safe on already-escaped content from Django's escape — safe
    def formatted_content(self, obj):
        from django.utils.html import escape
        escaped = escape(obj.content)
        return mark_safe(f'<pre>{escaped}</pre>')
    formatted_content.short_description = 'Content'


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'resource_type', 'resource_id', 'timestamp']
    list_filter = ['action', 'resource_type', 'timestamp']
    search_fields = ['resource_id', 'details']
    readonly_fields = [
        'user', 'action', 'resource_type', 'resource_id',
        'details', 'ip_address', 'user_agent', 'timestamp',
    ]

    # BUG-0067: Audit logs can be deleted from admin — no deletion protection (CWE-862, CVSS 5.3, MEDIUM, Tier 2)
    def has_delete_permission(self, request, obj=None):
        return True


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ['title', 'case', 'doc_type', 'generated_by', 'created_at']
    list_filter = ['doc_type', 'created_at']
    search_fields = ['title']
    readonly_fields = ['created_at']
