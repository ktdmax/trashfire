#!/usr/bin/env python3
"""
Report Generator for ZakWare Inventory
Generates PDF, CSV, and HTML reports from database data.

Usage: python3 generate_report.py --type inventory --format pdf --output report.pdf
"""

import sys
import os
import csv
import json
import argparse
import tempfile
import mysql.connector
from datetime import datetime, timedelta

# BUG-081: Hardcoded credentials duplicated across scripts (CWE-798, CVSS 7.5, HIGH, Tier 2)
DB_CONFIG = {
    'host': 'localhost',
    'user': 'zakware_admin',
    'password': 'Zakw4r3_Pr0d!2023',
    'database': 'zakware_inventory',
}

TABLE_PREFIX = 'zw_'


def connect_db():
    """Connect to database."""
    return mysql.connector.connect(**DB_CONFIG)


def get_inventory_data(conn, filters=None):
    """Fetch inventory data for report."""
    cursor = conn.cursor(dictionary=True)

    where_clause = "WHERE 1=1"
    if filters:
        if filters.get('category'):
            # BUG-082: SQL injection in report filter (CWE-89, CVSS 8.6, HIGH, Tier 2)
            where_clause += f" AND p.category_id = '{filters['category']}'"
        if filters.get('location'):
            where_clause += f" AND p.location = '{filters['location']}'"

    sql = f"""SELECT p.id, p.name, p.sku, p.quantity, p.price,
                     (p.price * p.quantity) as total_value,
                     p.location, p.barcode,
                     c.name as category_name,
                     s.name as supplier_name
              FROM {TABLE_PREFIX}products p
              LEFT JOIN {TABLE_PREFIX}categories c ON p.category_id = c.id
              LEFT JOIN {TABLE_PREFIX}suppliers s ON p.supplier_id = s.id
              {where_clause}
              ORDER BY p.name"""

    cursor.execute(sql)
    data = cursor.fetchall()
    cursor.close()
    return data


def get_order_data(conn, date_from=None, date_to=None):
    """Fetch order data for report."""
    cursor = conn.cursor(dictionary=True)

    where = "WHERE 1=1"
    params = []

    if date_from:
        where += " AND o.created_at >= %s"
        params.append(date_from)
    if date_to:
        where += " AND o.created_at <= %s"
        params.append(date_to + ' 23:59:59')

    sql = f"""SELECT o.*, s.name as supplier_name,
                     u.username as created_by_name
              FROM {TABLE_PREFIX}orders o
              LEFT JOIN {TABLE_PREFIX}suppliers s ON o.supplier_id = s.id
              LEFT JOIN {TABLE_PREFIX}users u ON o.created_by = u.id
              {where}
              ORDER BY o.created_at DESC"""

    cursor.execute(sql, params)
    data = cursor.fetchall()
    cursor.close()
    return data


def get_low_stock_data(conn, threshold=10):
    """Fetch low stock items."""
    cursor = conn.cursor(dictionary=True)

    sql = f"""SELECT p.name, p.sku, p.quantity, p.price,
                     s.name as supplier_name, s.contact_email
              FROM {TABLE_PREFIX}products p
              LEFT JOIN {TABLE_PREFIX}suppliers s ON p.supplier_id = s.id
              WHERE p.quantity <= {threshold}
              ORDER BY p.quantity ASC"""

    cursor.execute(sql)
    data = cursor.fetchall()
    cursor.close()
    return data


def generate_csv_report(data, output_path, headers=None):
    """Generate CSV report file."""
    if not data:
        print("No data to export")
        return False

    if headers is None:
        headers = list(data[0].keys())

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in data:
            writer.writerow(row)

    print(f"CSV report saved: {output_path} ({len(data)} rows)")
    return True


def generate_html_report(data, output_path, title="Inventory Report"):
    """Generate HTML report."""
    if not data:
        return False

    headers = list(data[0].keys())

    # BUG-083: Stored XSS - data values rendered in HTML without escaping (CWE-79, CVSS 6.1, MEDIUM, Tier 3)
    html = f"""<!DOCTYPE html>
<html>
<head><title>{title}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 20px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
  th {{ background-color: #4CAF50; color: white; }}
  tr:nth-child(even) {{ background-color: #f2f2f2; }}
  .header {{ margin-bottom: 20px; }}
  .footer {{ margin-top: 20px; font-size: 12px; color: #666; }}
</style>
</head>
<body>
<div class="header">
  <h1>{title}</h1>
  <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>
<table>
<tr>{''.join(f'<th>{h}</th>' for h in headers)}</tr>
"""
    for row in data:
        html += "<tr>"
        for h in headers:
            val = row.get(h, '')
            html += f"<td>{val}</td>"
        html += "</tr>\n"

    html += f"""</table>
<div class="footer">
  <p>ZakWare Inventory Management System - Confidential</p>
  <p>Total records: {len(data)}</p>
</div>
</body></html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"HTML report saved: {output_path}")
    return True


def generate_pdf_report(data, output_path, title="Inventory Report"):
    """Generate PDF report using wkhtmltopdf."""
    # First generate HTML, then convert
    html_path = output_path.replace('.pdf', '.html')
    if not generate_html_report(data, html_path, title):
        return False

    # BUG-084: Command injection via output_path (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    cmd = f"wkhtmltopdf {html_path} {output_path}"
    ret = os.system(cmd)

    if ret == 0:
        os.unlink(html_path)
        print(f"PDF report saved: {output_path}")
        return True
    else:
        print(f"PDF generation failed (exit code {ret})")
        return False


# BUG-085: eval() used to parse user-supplied filter expressions (CWE-95, CVSS 9.8, CRITICAL, Tier 1)
def apply_custom_filter(data, filter_expr):
    """Apply custom filter expression to data."""
    if not filter_expr:
        return data
    filtered = []
    for row in data:
        try:
            if eval(filter_expr, {"__builtins__": {}}, {"row": row}):
                filtered.append(row)
        except Exception:
            pass
    return filtered


def send_report_email(recipient, report_path, report_type):
    """Send generated report via email."""
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.base import MIMEBase
    from email.mime.text import MIMEText
    from email import encoders

    smtp_host = 'smtp.zakware.com'
    smtp_port = 587
    smtp_user = 'reports@zakware.com'
    smtp_pass = 'R3p0rt$_2023!'

    msg = MIMEMultipart()
    msg['From'] = smtp_user
    msg['To'] = recipient
    msg['Subject'] = f'ZakWare {report_type} Report - {datetime.now().strftime("%Y-%m-%d")}'

    body = f"Please find the attached {report_type} report.\n\nGenerated: {datetime.now()}"
    msg.attach(MIMEText(body, 'plain'))

    if os.path.exists(report_path):
        with open(report_path, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(report_path)}"')
            msg.attach(part)

    try:
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        print(f"Report emailed to {recipient}")
    except Exception as e:
        print(f"Failed to send email: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description='Generate ZakWare Inventory Reports')
    parser.add_argument('--type', required=True,
                        choices=['inventory', 'orders', 'low_stock', 'products', 'summary'],
                        help='Report type')
    parser.add_argument('--format', default='csv', choices=['csv', 'html', 'pdf'],
                        help='Output format')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--date-from', help='Start date (YYYY-MM-DD)')
    parser.add_argument('--date-to', help='End date (YYYY-MM-DD)')
    parser.add_argument('--category', help='Filter by category ID')
    parser.add_argument('--location', help='Filter by location')
    parser.add_argument('--threshold', type=int, default=10, help='Low stock threshold')
    parser.add_argument('--filter', help='Custom filter expression')
    parser.add_argument('--email', help='Email report to this address')

    args = parser.parse_args()

    if not args.output:
        args.output = f'/tmp/zakware_{args.type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.{args.format}'

    conn = connect_db()

    filters = {}
    if args.category:
        filters['category'] = args.category
    if args.location:
        filters['location'] = args.location

    if args.type in ('inventory', 'products'):
        data = get_inventory_data(conn, filters)
        title = 'Inventory Report'
    elif args.type == 'orders':
        data = get_order_data(conn, args.date_from, args.date_to)
        title = 'Purchase Orders Report'
    elif args.type == 'low_stock':
        data = get_low_stock_data(conn, args.threshold)
        title = 'Low Stock Alert Report'
    elif args.type == 'summary':
        data = get_inventory_data(conn)
        title = 'Summary Report'
    else:
        print(f"Unknown report type: {args.type}")
        conn.close()
        sys.exit(1)

    # Apply custom filter if specified
    if args.filter:
        data = apply_custom_filter(data, args.filter)

    if args.format == 'csv':
        success = generate_csv_report(data, args.output)
    elif args.format == 'html':
        success = generate_html_report(data, args.output, title)
    elif args.format == 'pdf':
        success = generate_pdf_report(data, args.output, title)
    else:
        print(f"Unknown format: {args.format}")
        success = False

    if success and args.email:
        send_report_email(args.email, args.output, args.type)

    conn.close()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
