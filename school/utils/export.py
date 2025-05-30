"""Export utilities for data export to various formats."""

import io
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

# Check if required libraries are installed
try:
    import xlsxwriter
    EXCEL_AVAILABLE = True
except ImportError:
    logger.warning("XlsxWriter not installed. Excel export will not work.")
    EXCEL_AVAILABLE = False


def prepare_data_for_export(data: List, fieldnames: List[str]) -> List[Dict]:
    """Prepare data for export by converting objects to dictionaries.
    
    Args:
        data: List of data objects
        fieldnames: List of field names to include
        
    Returns:
        List of dictionaries with selected fields
    """
    result = []
    
    for item in data:
        row = {}
        for field in fieldnames:
            # Handle dictionary data
            if isinstance(item, dict):
                row[field] = item.get(field, '')
            # Handle model objects
            else:
                try:
                    row[field] = getattr(item, field, '')
                except AttributeError:
                    row[field] = ''
        result.append(row)
        
    return result


def generate_excel(data: List[Dict], fieldnames: List[str], sheet_name: str = "Sheet1") -> bytes:
    """Generate an Excel file from data.
    
    Args:
        data: List of dictionaries containing data
        fieldnames: List of field names to include
        sheet_name: Name for the Excel sheet
        
    Returns:
        Excel file as bytes
    """
    if not EXCEL_AVAILABLE:
        logger.error("XlsxWriter not installed. Cannot generate Excel file.")
        return b"Excel generation requires XlsxWriter library"
    
    output = io.BytesIO()
    
    # Create workbook and add a worksheet
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet(sheet_name)
    
    # Add a bold format for headers
    header_format = workbook.add_format({
        'bold': True,
        'bg_color': '#CCCCCC',
        'border': 1
    })
    
    # Add a number format
    number_format = workbook.add_format({'num_format': '#,##0.00'})
    
    # Add a date format
    date_format = workbook.add_format({'num_format': 'yyyy-mm-dd'})
    
    # Write headers
    for col, field in enumerate(fieldnames):
        worksheet.write(0, col, field, header_format)
    
    # Write data rows
    for row_idx, item in enumerate(data, start=1):
        for col_idx, field in enumerate(fieldnames):
            value = item.get(field, '')
            
            # Format numbers
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                worksheet.write_number(row_idx, col_idx, value, number_format)
            # Format dates
            elif hasattr(value, 'strftime'):
                worksheet.write_datetime(row_idx, col_idx, value, date_format)
            # Default string format
            else:
                worksheet.write(row_idx, col_idx, str(value))
    
    # Auto-fit columns
    for col_idx, _ in enumerate(fieldnames):
        worksheet.set_column(col_idx, col_idx, 15)  # Set width to 15 as a reasonable default
    
    workbook.close()
    
    return output.getvalue()
