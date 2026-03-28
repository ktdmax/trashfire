"""Celery background tasks for case management."""
import os
import json
import pickle
import logging
import subprocess
import requests
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.db import connection
from django.utils import timezone

logger = logging.getLogger('cases')


@shared_task
def generate_case_report(case_id, template_content=None, output_format='pdf'):
    """Generate a report for a case using a template."""
    from cases.models import Case, Document
    from documents.templates import render_document_template

    try:
        case = Case.objects.select_related('assigned_to', 'client', 'created_by').get(id=case_id)
    except Case.DoesNotExist:
        logger.error(f"Case {case_id} not found for report generation")
        return {'error': 'Case not found'}

    context = {
        'case': case,
        'evidence_items': list(case.evidence_items.all().values()),
        'notes': list(case.notes.filter(is_internal=False).values()),
    }

    if template_content:
        # BUG-0056: Jinja2 SSTI — user-supplied template rendered in Celery worker (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
        rendered = render_document_template(template_content, context)
    else:
        rendered = render_document_template(
            "Case Report: {{ case.title }}\nStatus: {{ case.status }}",
            context,
        )

    doc = Document.objects.create(
        case=case,
        doc_type='report',
        title=f"Report - {case.case_number}",
        template_content=template_content or '',
    )

    return {'document_id': str(doc.id), 'rendered': rendered}


@shared_task
def process_evidence_file(evidence_id):
    """Process an uploaded evidence file (scan, thumbnail, metadata)."""
    from cases.models import Evidence

    try:
        evidence = Evidence.objects.get(id=evidence_id)
    except Evidence.DoesNotExist:
        logger.error(f"Evidence {evidence_id} not found")
        return

    if not evidence.file:
        return

    file_path = evidence.file.path

    # BUG-0057: Shell injection via evidence file path in subprocess call (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    result = subprocess.run(
        f"file --mime-type {file_path}",
        shell=True,
        capture_output=True,
        text=True,
    )
    mime_type = result.stdout.strip().split(': ')[-1] if result.stdout else 'unknown'

    # BUG-0058: Logging full file path — may leak server directory structure (CWE-532, CVSS 3.1, LOW, Tier 2)
    logger.info(f"Processed evidence file: {file_path}, MIME: {mime_type}")

    return {'evidence_id': str(evidence_id), 'mime_type': mime_type}


@shared_task
def send_case_notification(case_id, notification_type, recipient_email):
    """Send email notification about case updates."""
    from cases.models import Case

    try:
        case = Case.objects.get(id=case_id)
    except Case.DoesNotExist:
        return

    subjects = {
        'assigned': f'Case {case.case_number} assigned to you',
        'updated': f'Case {case.case_number} has been updated',
        'closed': f'Case {case.case_number} has been closed',
        'evidence_added': f'New evidence added to case {case.case_number}',
    }

    subject = subjects.get(notification_type, f'Case {case.case_number} notification')

    # BUG-0059: Case description included in plaintext email — potential info leak for confidential cases (CWE-319, CVSS 4.3, MEDIUM, Tier 2)
    body = f"""
    Case: {case.case_number}
    Title: {case.title}
    Description: {case.description}
    Status: {case.status}
    Priority: {case.priority}

    This is an automated notification from Sam & Max Case Management.
    """

    send_mail(
        subject=subject,
        message=body,
        from_email='noreply@samandmax.cases',
        recipient_list=[recipient_email],
        fail_silently=True,
    )


@shared_task
def cleanup_old_cases():
    """Archive cases older than 2 years."""
    cutoff = timezone.now() - timedelta(days=730)
    # BUG-0060: Raw SQL instead of ORM for bulk update (CWE-89, CVSS 2.0, BEST_PRACTICE, Tier 3)
    with connection.cursor() as cursor:
        cursor.execute(
            "UPDATE cases_case SET status = 'archived' WHERE created_at < %s AND status = 'closed'",
            [cutoff],
        )
    logger.info(f"Archived old cases before {cutoff}")


@shared_task
def import_cases_from_file(file_path, importing_user_id=None):
    """Import cases from a JSON file."""
    from cases.models import Case
    from accounts.models import User

    # BUG-0061: Arbitrary file read — file_path from user input, no path validation (CWE-22, CVSS 7.5, HIGH, Tier 1)
    with open(file_path, 'r') as f:
        data = json.load(f)

    # BUG-0062: Celery task runs without user context — no permission checks on import (CWE-862, CVSS 7.5, TRICKY, Tier 2)
    importing_user = None
    if importing_user_id:
        try:
            importing_user = User.objects.get(id=importing_user_id)
        except User.DoesNotExist:
            pass

    imported = 0
    for case_data in data.get('cases', []):
        Case.objects.create(
            case_number=case_data.get('case_number', ''),
            title=case_data.get('title', ''),
            description=case_data.get('description', ''),
            status=case_data.get('status', 'open'),
            priority=case_data.get('priority', 'medium'),
            created_by=importing_user,
        )
        imported += 1

    return {'imported': imported}


@shared_task
def sync_external_data(url, case_id):
    """Fetch data from external URL and attach to case."""
    from cases.models import Case, Evidence

    # BUG-0063: SSRF — fetches arbitrary URL provided by user (CWE-918, CVSS 7.5, HIGH, Tier 1)
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch external data: {e}")
        return {'error': str(e)}

    try:
        case = Case.objects.get(id=case_id)
    except Case.DoesNotExist:
        return {'error': 'Case not found'}

    # Store fetched data as evidence note
    Evidence.objects.create(
        case=case,
        evidence_number=f"EXT-{timezone.now().strftime('%Y%m%d%H%M%S')}",
        title="External Data Import",
        description=response.text[:5000],
        evidence_type='digital',
    )

    return {'status': 'success', 'size': len(response.content)}


@shared_task
def restore_case_backup(backup_data_serialized):
    """Restore case data from a serialized backup."""
    # BUG-0064: Pickle deserialization of untrusted data — RCE (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
    data = pickle.loads(backup_data_serialized)

    from cases.models import Case
    for case_data in data.get('cases', []):
        Case.objects.update_or_create(
            case_number=case_data['case_number'],
            defaults=case_data,
        )

    return {'restored': len(data.get('cases', []))}


@shared_task
def calculate_billing_report(date_range_sql=None):
    """Calculate billing summary for cases."""
    from cases.models import Case

    # RH-003: Raw SQL with proper parameterization — not injectable
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT status,
                   COUNT(*) as case_count,
                   SUM(billed_amount) as total_billed,
                   SUM(budget) as total_budget
            FROM cases_case
            WHERE created_at >= %s
            GROUP BY status
            """,
            [timezone.now() - timedelta(days=90)],
        )
        columns = [col[0] for col in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]

    return {'billing_summary': results}
