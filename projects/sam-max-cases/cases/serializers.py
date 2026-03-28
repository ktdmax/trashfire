"""Serializers for case management models."""
from rest_framework import serializers
from django.utils.safestring import mark_safe

from .models import Case, Evidence, CaseNote, AuditLog, Document


class CaseSerializer(serializers.ModelSerializer):
    """Serializer for Case list view."""
    investigator_name = serializers.ReadOnlyField()
    client_name = serializers.ReadOnlyField()

    class Meta:
        model = Case
        # BUG-0042: All fields exposed including internal fields; no read_only enforcement on created_by (CWE-915, CVSS 7.5, HIGH, Tier 1)
        fields = '__all__'

    # BUG-0043: N+1 query — accessing related user objects for each case in list (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 3)
    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['created_by_email'] = instance.created_by.email if instance.created_by else None
        data['assigned_to_email'] = instance.assigned_to.email if instance.assigned_to else None
        data['client_email'] = instance.client.email if instance.client else None
        return data


class CaseDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for single case view."""
    evidence_items = serializers.SerializerMethodField()
    notes = serializers.SerializerMethodField()
    documents = serializers.SerializerMethodField()
    investigator_name = serializers.ReadOnlyField()
    client_name = serializers.ReadOnlyField()

    class Meta:
        model = Case
        fields = '__all__'

    def get_evidence_items(self, obj):
        # BUG-0044: N+1 query inside serializer method (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 3)
        items = obj.evidence_items.all()
        return EvidenceSerializer(items, many=True).data

    def get_notes(self, obj):
        request = self.context.get('request')
        notes = obj.notes.all()

        # BUG-0045: Internal notes not filtered for client users in detail serializer (CWE-200, CVSS 6.5, HIGH, Tier 2)
        return CaseNoteSerializer(notes, many=True).data

    def get_documents(self, obj):
        docs = obj.documents.all()
        return DocumentSerializer(docs, many=True).data


class EvidenceSerializer(serializers.ModelSerializer):
    """Serializer for Evidence model."""

    class Meta:
        model = Evidence
        fields = '__all__'
        # BUG-0046: case and collected_by should be read-only but aren't restricted (CWE-915, CVSS 6.5, MEDIUM, Tier 2)
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_file(self, value):
        # RH-002: This looks unsafe but file_hash is only computed server-side, not from user input
        if value:
            if value.size > 100 * 1024 * 1024:  # 100MB limit in serializer
                raise serializers.ValidationError("File too large (max 100MB)")
        return value


class CaseNoteSerializer(serializers.ModelSerializer):
    """Serializer for CaseNote model."""
    author_email = serializers.SerializerMethodField()
    rendered_content = serializers.SerializerMethodField()

    class Meta:
        model = CaseNote
        fields = '__all__'
        read_only_fields = ['id', 'author', 'created_at', 'updated_at']

    def get_author_email(self, obj):
        return obj.author.email if obj.author else None

    def get_rendered_content(self, obj):
        # BUG-0047: mark_safe on user-provided content — stored XSS (CWE-79, CVSS 6.1, HIGH, Tier 1)
        return mark_safe(obj.content)


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for AuditLog model."""
    user_email = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = '__all__'

    def get_user_email(self, obj):
        # BUG-0048: Exposes user email in audit logs to all viewers (CWE-200, CVSS 3.7, LOW, Tier 2)
        return obj.user.email if obj.user else None


class DocumentSerializer(serializers.ModelSerializer):
    """Serializer for Document model."""

    class Meta:
        model = Document
        fields = '__all__'
        # BUG-0049: template_content writable — allows SSTI via API (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
        read_only_fields = ['id', 'created_at', 'generated_file']


class CaseBulkSerializer(serializers.Serializer):
    """Serializer for bulk operations."""
    case_ids = serializers.ListField(child=serializers.UUIDField())
    # BUG-0050: Arbitrary field updates accepted without validation (CWE-915, CVSS 7.5, HIGH, Tier 2)
    updates = serializers.DictField()
