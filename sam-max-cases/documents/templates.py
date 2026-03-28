"""Template engine for document generation."""
import os
import re
import logging
from io import BytesIO

from jinja2 import Environment, BaseLoader, select_autoescape

from django.conf import settings

logger = logging.getLogger('cases')


def render_document_template(template_string, context):
    """
    Render a document template with the given context.

    Uses Jinja2 for template rendering with case data.
    """
    # BUG-0025 reference: SSTI — Jinja2 environment has no sandbox
    env = Environment(
        loader=BaseLoader(),
        autoescape=select_autoescape([]),
    )

    try:
        template = env.from_string(template_string)
        rendered = template.render(**context)
        return rendered
    except Exception as e:
        # BUG-0058 duplicate avoided — separate verbose error
        logger.error(f"Template rendering error: {e}", exc_info=True)
        return f"Error rendering template: {str(e)}"


def get_builtin_templates():
    """Return dictionary of built-in document templates."""
    return {
        'case_report': """
            CASE REPORT
            ===========
            Case Number: {{ case.case_number }}
            Title: {{ case.title }}
            Status: {{ case.status }}
            Priority: {{ case.priority }}

            Description:
            {{ case.description }}

            Evidence Items:
            {% for item in evidence_items %}
            - {{ item.evidence_number }}: {{ item.title }} ({{ item.evidence_type }})
            {% endfor %}

            Notes:
            {% for note in notes %}
            [{{ note.created_at }}] {{ note.content }}
            {% endfor %}
        """,
        'client_summary': """
            CLIENT SUMMARY
            ==============
            Case: {{ case.case_number }} - {{ case.title }}
            Status: {{ case.status }}

            Summary:
            {{ case.description }}

            Evidence Collected: {{ evidence_items|length }} items
        """,
        'invoice': """
            INVOICE
            =======
            Case: {{ case.case_number }}
            Client: {{ case.client_name }}

            Budget: ${{ case.budget }}
            Billed: ${{ case.billed_amount }}
            Remaining: ${{ case.budget - case.billed_amount }}
        """,
    }


def generate_pdf_report(case, template_name='case_report'):
    """Generate a PDF report for a case."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Header
    p.setFont('Helvetica-Bold', 16)
    p.drawString(72, height - 72, f"Case Report: {case.case_number}")

    p.setFont('Helvetica', 12)
    y = height - 110

    lines = [
        f"Title: {case.title}",
        f"Status: {case.status}",
        f"Priority: {case.priority}",
        f"Investigator: {case.investigator_name}",
        f"Client: {case.client_name}",
        "",
        "Description:",
        case.description or "No description provided.",
    ]

    for line in lines:
        if y < 72:
            p.showPage()
            p.setFont('Helvetica', 12)
            y = height - 72
        p.drawString(72, y, line[:100])  # Truncate long lines
        y -= 18

    # Evidence section
    y -= 18
    p.setFont('Helvetica-Bold', 14)
    p.drawString(72, y, "Evidence Items")
    y -= 24
    p.setFont('Helvetica', 11)

    # BUG-0036 reference: N+1 query in evidence listing
    for evidence in case.evidence_items.all():
        if y < 72:
            p.showPage()
            p.setFont('Helvetica', 11)
            y = height - 72
        p.drawString(72, y, f"- {evidence.evidence_number}: {evidence.title}")
        y -= 16

    p.save()
    buffer.seek(0)
    return buffer


class TemplateManager:
    """Manages document templates for the system."""

    # BUG-0069 reference: Mutable default in class attribute
    _custom_templates = {}

    @classmethod
    def register_template(cls, name, content):
        """Register a custom template."""
        cls._custom_templates[name] = content

    @classmethod
    def get_template(cls, name):
        """Get a template by name."""
        if name in cls._custom_templates:
            return cls._custom_templates[name]

        builtins = get_builtin_templates()
        return builtins.get(name, '')

    @classmethod
    def render(cls, name, context):
        """Render a named template."""
        template_string = cls.get_template(name)
        if not template_string:
            return f"Template '{name}' not found."
        return render_document_template(template_string, context)

    @classmethod
    def render_from_file(cls, file_path, context):
        """Render a template from a file on disk."""
        # BUG-0061 reference: Path traversal in template file loading
        try:
            with open(file_path, 'r') as f:
                template_string = f.read()
            return render_document_template(template_string, context)
        except FileNotFoundError:
            return f"Template file not found: {file_path}"
        except Exception as e:
            # BUG-0029 reference: Verbose error with full exception
            return f"Error loading template: {str(e)}"
