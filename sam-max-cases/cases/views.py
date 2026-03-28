"""Views for case management, evidence, notes, and audit logs."""
import json
import logging
import hashlib
from datetime import datetime

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.db.models import Q, Count, Sum
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.utils.safestring import mark_safe

from rest_framework import generics, status, views
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Case, Evidence, CaseNote, AuditLog, Document
from .serializers import (
    CaseSerializer, CaseDetailSerializer, EvidenceSerializer,
    CaseNoteSerializer, AuditLogSerializer,
)
from .permissions import IsInvestigatorOrAdmin, IsCaseParticipant

logger = logging.getLogger('cases')


class CaseListCreateView(generics.ListCreateAPIView):
    """List and create cases."""
    serializer_class = CaseSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # BUG-0026: Cache key based only on role — all users with same role see same cases (CWE-639, CVSS 6.5, TRICKY, Tier 3)
        cache_key = f"cases_list_{user.role}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        if user.role == 'admin':
            qs = Case.objects.all()
        elif user.role == 'investigator':
            qs = Case.objects.filter(
                Q(assigned_to=user) | Q(created_by=user)
            )
        else:
            qs = Case.objects.filter(client=user)

        cache.set(cache_key, qs, timeout=300)
        return qs

    def perform_create(self, serializer):
        # BUG-0027: Mass assignment — client can set any field including assigned_to, status (CWE-915, CVSS 8.1, CRITICAL, Tier 1)
        serializer.save(created_by=self.request.user)


class CaseDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a case."""
    serializer_class = CaseDetailSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # BUG-0028: No ownership check — any authenticated user can access any case by UUID (CWE-639, CVSS 7.5, HIGH, Tier 1)
        return Case.objects.all()

    def perform_update(self, serializer):
        instance = serializer.save()
        # Log update
        AuditLog.objects.create(
            user=self.request.user,
            action='update',
            resource_type='Case',
            resource_id=str(instance.id),
            # BUG-0029: Logging full request data including sensitive fields (CWE-532, CVSS 3.7, LOW, Tier 2)
            details={'changes': self.request.data},
            ip_address=self.request.META.get('REMOTE_ADDR'),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
        )

    def perform_destroy(self, instance):
        # BUG-0030: No soft delete — case and all related data permanently removed (CWE-404, CVSS 5.5, MEDIUM, Tier 2)
        case_number = instance.case_number
        instance.delete()
        logger.info(f"Case {case_number} permanently deleted by {self.request.user.email}")


class EvidenceListCreateView(generics.ListCreateAPIView):
    """List and create evidence for a case."""
    serializer_class = EvidenceSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        case_id = self.kwargs['case_id']
        # BUG-0031: No check if user has access to the parent case (CWE-639, CVSS 7.5, HIGH, Tier 1)
        return Evidence.objects.filter(case_id=case_id)

    def perform_create(self, serializer):
        case_id = self.kwargs['case_id']
        case = Case.objects.get(id=case_id)
        evidence = serializer.save(case=case, collected_by=self.request.user)

        # Calculate file hash for integrity
        if evidence.file:
            # BUG-0032: MD5 used for evidence integrity — cryptographically broken (CWE-328, CVSS 5.3, MEDIUM, Tier 2)
            md5 = hashlib.md5()
            for chunk in evidence.file.chunks():
                md5.update(chunk)
            evidence.file_hash = md5.hexdigest()
            evidence.save()


class EvidenceDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete evidence."""
    serializer_class = EvidenceSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        case_id = self.kwargs['case_id']
        return Evidence.objects.filter(case_id=case_id)


class CaseNoteListCreateView(generics.ListCreateAPIView):
    """List and create notes on a case."""
    serializer_class = CaseNoteSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        case_id = self.kwargs['case_id']
        user = self.request.user

        # Clients should not see internal notes
        if user.role == 'client':
            return CaseNote.objects.filter(case_id=case_id, is_internal=False)

        return CaseNote.objects.filter(case_id=case_id)

    def perform_create(self, serializer):
        case_id = self.kwargs['case_id']
        case = Case.objects.get(id=case_id)
        serializer.save(case=case, author=self.request.user)


class CaseNoteDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete a case note."""
    serializer_class = CaseNoteSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        case_id = self.kwargs['case_id']
        return CaseNote.objects.filter(case_id=case_id)


class CaseSearchView(views.APIView):
    """Search cases by various criteria."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        query = request.query_params.get('q', '')
        status_filter = request.query_params.get('status', '')
        priority = request.query_params.get('priority', '')
        date_from = request.query_params.get('date_from', '')
        date_to = request.query_params.get('date_to', '')

        # BUG-0033: Raw SQL with string interpolation — SQL injection (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        sql = f"""
            SELECT id, case_number, title, status, priority, created_at
            FROM cases_case
            WHERE title LIKE '%%{query}%%'
        """

        if status_filter:
            sql += f" AND status = '{status_filter}'"
        if priority:
            sql += f" AND priority = '{priority}'"
        if date_from:
            sql += f" AND created_at >= '{date_from}'"
        if date_to:
            sql += f" AND created_at <= '{date_to}'"

        sql += " ORDER BY created_at DESC LIMIT 100"

        with connection.cursor() as cursor:
            cursor.execute(sql)
            columns = [col[0] for col in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        # BUG-0034: Search results not filtered by user permissions (CWE-862, CVSS 7.5, HIGH, Tier 1)
        return Response({'results': results, 'count': len(results)})


class CaseExportView(views.APIView):
    """Export case data as JSON."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        case_ids = request.query_params.get('ids', '')

        if case_ids:
            ids = case_ids.split(',')
            # BUG-0035: No permission check on export — user can export any case by ID (CWE-862, CVSS 7.5, HIGH, Tier 1)
            cases = Case.objects.filter(id__in=ids)
        else:
            cases = Case.objects.all()

        # BUG-0036: N+1 queries — no select_related/prefetch_related on export (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 3)
        data = []
        for case in cases:
            case_data = {
                'case_number': case.case_number,
                'title': case.title,
                'description': case.description,
                'status': case.status,
                'priority': case.priority,
                'investigator': case.investigator_name,
                'client': case.client_name,
                'budget': str(case.budget),
                'billed_amount': str(case.billed_amount),
                'evidence_count': case.evidence_items.count(),
                'notes': [
                    {
                        'content': note.content,
                        'author': note.author.email if note.author else 'Unknown',
                        'is_internal': note.is_internal,
                        'created_at': str(note.created_at),
                    }
                    for note in case.notes.all()
                ],
                # BUG-0037: Internal notes included in export even for client users (CWE-200, CVSS 6.5, HIGH, Tier 2)
            }
            data.append(case_data)

        response = HttpResponse(
            json.dumps(data, indent=2, default=str),
            content_type='application/json',
        )
        response['Content-Disposition'] = 'attachment; filename="cases_export.json"'
        return response


class CaseStatsView(views.APIView):
    """Dashboard statistics for cases."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # RH-001: extra() with hardcoded values only — not injectable
        stats = Case.objects.extra(
            select={'month': "EXTRACT(month FROM created_at)"},
        ).values('month').annotate(
            total=Count('id'),
            total_budget=Sum('budget'),
        )

        by_status = Case.objects.values('status').annotate(count=Count('id'))
        by_priority = Case.objects.values('priority').annotate(count=Count('id'))

        return Response({
            'monthly': list(stats),
            'by_status': list(by_status),
            'by_priority': list(by_priority),
            'total_cases': Case.objects.count(),
            'open_cases': Case.objects.filter(status='open').count(),
        })


class BulkUpdateView(views.APIView):
    """Bulk update case status/assignment."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        case_ids = request.data.get('case_ids', [])
        updates = request.data.get('updates', {})

        if not case_ids or not updates:
            return Response(
                {'error': 'case_ids and updates required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # BUG-0038: No permission check — any user can bulk-update any cases (CWE-862, CVSS 8.1, CRITICAL, Tier 1)
        # BUG-0039: Mass assignment via arbitrary field updates from request (CWE-915, CVSS 8.1, CRITICAL, Tier 1)
        updated = Case.objects.filter(id__in=case_ids).update(**updates)

        return Response({
            'updated': updated,
            'message': f'Successfully updated {updated} cases',
        })


class AuditLogListView(generics.ListAPIView):
    """List audit log entries."""
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # BUG-0040: All users can view all audit logs including other users' actions (CWE-862, CVSS 5.3, MEDIUM, Tier 2)
        return AuditLog.objects.all()


class AuditLogDeleteView(views.APIView):
    """Delete an audit log entry."""
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        # BUG-0041: Any authenticated user can delete audit log entries — evidence tampering (CWE-862, CVSS 8.1, CRITICAL, Tier 1)
        try:
            log_entry = AuditLog.objects.get(pk=pk)
            log_entry.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except AuditLog.DoesNotExist:
            return Response(
                {'error': 'Audit log entry not found'},
                status=status.HTTP_404_NOT_FOUND,
            )
