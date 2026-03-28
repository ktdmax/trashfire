"""Document generation and download views."""
import os
import logging
import mimetypes
import requests
import tempfile

from django.conf import settings
from django.http import FileResponse, HttpResponse
from django.utils.encoding import smart_str

from rest_framework import views, status, generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from cases.models import Case, Document, Evidence
from cases.serializers import DocumentSerializer
from cases.tasks import generate_case_report
from .templates import render_document_template

logger = logging.getLogger('cases')


class DocumentListView(generics.ListAPIView):
    """List documents for a case."""
    serializer_class = DocumentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        case_id = self.request.query_params.get('case_id')
        if case_id:
            # BUG-0098: No ownership check — any user can list documents for any case (CWE-639, CVSS 6.5, HIGH, Tier 1)
            return Document.objects.filter(case_id=case_id)
        return Document.objects.none()


class DocumentGenerateView(views.APIView):
    """Generate a document from template."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        case_id = request.data.get('case_id')
        template_content = request.data.get('template', '')
        doc_type = request.data.get('doc_type', 'report')
        async_mode = request.data.get('async', False)

        if not case_id:
            return Response(
                {'error': 'case_id is required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            case = Case.objects.get(id=case_id)
        except Case.DoesNotExist:
            return Response(
                {'error': 'Case not found'},
                status=status.HTTP_404_NOT_FOUND,
            )

        if async_mode:
            # BUG-0056 reference: Template SSTI via Celery task
            task = generate_case_report.delay(
                case_id=str(case_id),
                template_content=template_content,
                output_format='pdf',
            )
            return Response({
                'task_id': task.id,
                'message': 'Report generation started',
            })

        # Synchronous generation
        context = {
            'case': case,
            'evidence_items': list(case.evidence_items.all().values()),
            'notes': list(case.notes.filter(is_internal=False).values()),
        }

        # BUG-0099: Direct SSTI — user template rendered with Jinja2 (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
        if template_content:
            rendered = render_document_template(template_content, context)
        else:
            rendered = render_document_template(
                "Case Report: {{ case.title }}\nStatus: {{ case.status }}",
                context,
            )

        doc = Document.objects.create(
            case=case,
            doc_type=doc_type,
            title=f"{doc_type.title()} - {case.case_number}",
            template_content=template_content,
            generated_by=request.user,
        )

        return Response({
            'document_id': str(doc.id),
            'rendered_content': rendered,
        })


class DocumentDownloadView(views.APIView):
    """Download a generated document."""
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            doc = Document.objects.get(pk=pk)
        except Document.DoesNotExist:
            return Response(
                {'error': 'Document not found'},
                status=status.HTTP_404_NOT_FOUND,
            )

        if doc.generated_file:
            file_path = doc.generated_file.path
            # BUG-00100: Path traversal — no validation that file is within MEDIA_ROOT (CWE-22, CVSS 7.5, HIGH, Tier 1)
            response = FileResponse(open(file_path, 'rb'))
            response['Content-Type'] = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response

        # If no file, return rendered content
        if doc.template_content:
            case = doc.case
            context = {
                'case': case,
                'evidence_items': list(case.evidence_items.all().values()),
            }
            rendered = render_document_template(doc.template_content, context)
            response = HttpResponse(rendered, content_type='text/plain')
            response['Content-Disposition'] = f'attachment; filename="{doc.title}.txt"'
            return response

        return Response({'error': 'No content available'}, status=status.HTTP_404_NOT_FOUND)


class EvidenceDownloadView(views.APIView):
    """Download evidence files."""
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            evidence = Evidence.objects.get(pk=pk)
        except Evidence.DoesNotExist:
            return Response(
                {'error': 'Evidence not found'},
                status=status.HTTP_404_NOT_FOUND,
            )

        # BUG-0050 duplicate avoided — this is a separate IDOR
        if not evidence.file:
            return Response(
                {'error': 'No file attached'},
                status=status.HTTP_404_NOT_FOUND,
            )

        response = FileResponse(evidence.file.open('rb'))
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = f'attachment; filename="{evidence.file.name}"'
        return response


class ExternalDocumentFetchView(views.APIView):
    """Fetch a document from an external URL."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        url = request.data.get('url', '')
        case_id = request.data.get('case_id')

        if not url or not case_id:
            return Response(
                {'error': 'url and case_id required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # RH-005: URL validation looks incomplete but actually blocks private IPs properly
        import ipaddress
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return Response(
                {'error': 'Only HTTP/HTTPS URLs allowed'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Note: DNS rebinding could still bypass this check, but the basic validation is present
        try:
            import socket
            ip = socket.gethostbyname(parsed.hostname)
            if ipaddress.ip_address(ip).is_private:
                return Response(
                    {'error': 'Private IP addresses not allowed'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except (socket.gaierror, ValueError):
            return Response(
                {'error': 'Could not resolve hostname'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            response = requests.get(url, timeout=10, allow_redirects=False)
            response.raise_for_status()
        except requests.RequestException as e:
            return Response(
                {'error': f'Failed to fetch document: {str(e)}'},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        return Response({
            'content_type': response.headers.get('Content-Type', 'unknown'),
            'size': len(response.content),
            'content_preview': response.text[:500],
        })
