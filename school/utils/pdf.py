"""PDF generation utilities."""

import io
import logging
import os
from datetime import datetime
from typing import Dict, List

# Install reportlab with: pip install reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image

logger = logging.getLogger(__name__)

# Check if reportlab is installed
try:
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    logger.warning("ReportLab not installed. PDF generation will not work.")
    REPORTLAB_AVAILABLE = False


def generate_pdf(data: List[Dict], fieldnames: List[str], title: str = "Report") -> bytes:
    """Generate a PDF document from data.
    
    Args:
        data: List of dictionaries containing the data
        fieldnames: List of field names to include in the PDF
        title: Title for the PDF document
        
    Returns:
        PDF document as bytes
    """
    if not REPORTLAB_AVAILABLE:
        logger.error("ReportLab not installed. Cannot generate PDF.")
        return b"PDF generation requires ReportLab library"
    
    buffer = io.BytesIO()
    
    # Create PDF document
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Define styles
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    subtitle_style = styles['Heading2']
    normal_style = styles['Normal']
    
    # Add title
    elements.append(Paragraph(title, title_style))
    elements.append(Spacer(1, 0.5*inch))
    
    # Add date
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Spacer(1, 0.25*inch))
    
    # Prepare table data
    table_data = [fieldnames]  # Header row
    
    for item in data:
        row = []
        for field in fieldnames:
            value = item.get(field, '')
            # Format dates
            if isinstance(value, (datetime, datetime.date)):
                value = value.strftime('%Y-%m-%d')
            row.append(str(value))
        table_data.append(row)
    
    # Create table
    table = Table(table_data)
    
    # Style the table
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ])
    
    # Add alternating row colors
    for i in range(1, len(table_data)):
        if i % 2 == 0:
            style.add('BACKGROUND', (0, i), (-1, i), colors.lightgrey)
    
    table.setStyle(style)
    elements.append(table)
    
    # Build PDF
    doc.build(elements)
    
    pdf_data = buffer.getvalue()
    buffer.close()
    
    return pdf_data


def generate_fee_receipt(receipt_data: Dict) -> bytes:
    """Generate a fee receipt PDF.
    
    Args:
        receipt_data: Dictionary containing receipt information
        
    Returns:
        PDF document as bytes
    """
    if not REPORTLAB_AVAILABLE:
        logger.error("ReportLab not installed. Cannot generate receipt PDF.")
        return b"PDF generation requires ReportLab library"
    
    buffer = io.BytesIO()
    
    # Create PDF
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Define styles
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    subtitle_style = styles['Heading2']
    normal_style = styles['Normal']
    
    # Custom styles
    receipt_style = ParagraphStyle(
        'Receipt',
        parent=styles['Heading1'],
        alignment=1,  # Center alignment
        spaceAfter=12
    )
    
    # Add school name
    elements.append(Paragraph(receipt_data.get('school_name', 'School Fee Receipt'), receipt_style))
    
    # Add school address if available
    if 'school_address' in receipt_data:
        elements.append(Paragraph(receipt_data['school_address'], ParagraphStyle(
            'Address',
            parent=styles['Normal'],
            alignment=1,
            spaceAfter=12
        )))
    
    elements.append(Spacer(1, 0.25*inch))
    
    # Add receipt title and number
    elements.append(Paragraph(f"RECEIPT #{receipt_data.get('receipt_no', '')}", subtitle_style))
    elements.append(Paragraph(f"Date: {receipt_data.get('date', datetime.now().strftime('%Y-%m-%d'))}", normal_style))
    
    elements.append(Spacer(1, 0.25*inch))
    
    # Student details
    student_data = [
        ['Student Name:', receipt_data.get('student_name', '')],
        ['PEN Number:', receipt_data.get('pen_num', '')],
        ['Admission Number:', receipt_data.get('admission_number', '')],
        ['Class:', receipt_data.get('class', '')],
        ['Father\'s Name:', receipt_data.get('father_name', '')]
    ]
    
    student_table = Table(student_data, colWidths=[2*inch, 3*inch])
    student_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
    ]))
    
    elements.append(student_table)
    elements.append(Spacer(1, 0.25*inch))
    
    # Payment details
    payment_data = [
        ['Academic Year:', receipt_data.get('academic_year', '')],
        ['Fee Type:', receipt_data.get('fee_type', '')],
        ['Term:', receipt_data.get('term', '')],
        ['Payment Method:', receipt_data.get('payment_type', '')],
        ['Amount Paid:', f"₹{receipt_data.get('amount_paid', 0):.2f}"],
        ['Amount Due:', f"₹{receipt_data.get('amount_due', 0):.2f}"]
    ]
    
    payment_table = Table(payment_data, colWidths=[2*inch, 3*inch])
    payment_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('BACKGROUND', (-1, -2), (-1, -2), colors.palegreen),  # Highlight paid amount
        ('BACKGROUND', (-1, -1), (-1, -1), colors.lightcoral if receipt_data.get('amount_due', 0) > 0 else colors.white),  # Highlight due amount if positive
    ]))
    
    elements.append(payment_table)
    elements.append(Spacer(1, 0.5*inch))
    
    # Signature
    elements.append(Paragraph("This is a computer generated receipt and does not require signature.", normal_style))
    elements.append(Spacer(1, 0.25*inch))
    elements.append(Paragraph(f"Cashier: {receipt_data.get('cashier', 'Admin')}", normal_style))
    
    # Build PDF
    doc.build(elements)
    
    pdf_data = buffer.getvalue()
    buffer.close()
    
    return pdf_data
