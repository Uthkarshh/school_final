"""
Backup service for automated Google Sheets backup.
"""

import os
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

import gspread
from google.oauth2.service_account import Credentials
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

class BackupService:
    """Service class for handling automated backups to Google Sheets."""
    
    def __init__(self, app):
        """Initialize the backup service with Flask app context."""
        self.app = app
        self.gc = None
        self.spreadsheet = None
        self._initialize_sheets_client()
    
    def _initialize_sheets_client(self):
        """Initialize Google Sheets client with service account credentials."""
        try:
            # Google Sheets API configuration
            credentials_path = os.getenv('GOOGLE_SHEETS_CREDENTIALS_PATH')
            spreadsheet_url = os.getenv('GOOGLE_SHEETS_BACKUP_URL')
            
            if not credentials_path:
                logger.warning("Google Sheets credentials path not configured. Backup disabled.")
                return
                
            if not spreadsheet_url:
                logger.warning("Google Sheets backup URL not configured. Backup disabled.")
                return
            
            if not os.path.exists(credentials_path):
                logger.error(f"Google Sheets credentials file not found: {credentials_path}")
                return
            
            # Define the scope
            scope = [
                'https://spreadsheets.google.com/feeds',
                'https://www.googleapis.com/auth/drive'
            ]
            
            # Authenticate with service account
            credentials = Credentials.from_service_account_file(credentials_path, scopes=scope)
            self.gc = gspread.authorize(credentials)
            
            # Open the spreadsheet
            self.spreadsheet = self.gc.open_by_url(spreadsheet_url)
            
            logger.info("Google Sheets client initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Google Sheets client: {e}")
            self.gc = None
            self.spreadsheet = None
    
    def run_nightly_backup(self):
        """Run the nightly backup process."""
        if not self.gc or not self.spreadsheet:
            logger.error("Google Sheets client not initialized. Skipping backup.")
            return
        
        with self.app.app_context():
            try:
                logger.info("Starting nightly database backup to Google Sheets")
                
                # Import models here to avoid circular imports
                from school.models import Student, ClassDetails, Fee, FeeBreakdown, Transport, ActivityLog
                
                # Define table configurations
                table_configs = {
                    'Students': {
                        'model': Student,
                        'fields': ['pen_num', 'admission_number', 'aadhar_number', 'student_name', 
                                 'father_name', 'mother_name', 'gender', 'date_of_birth', 
                                 'date_of_joining', 'contact_number', 'village', 'created_at', 
                                 'created_by', 'updated_by']
                    },
                    'Class_Details': {
                        'model': ClassDetails,
                        'fields': ['pen_num', 'year', 'current_class', 'section', 'roll_number', 
                                 'photo_id', 'language', 'vocational', 'currently_enrolled', 
                                 'created_at', 'created_by', 'updated_by']
                    },
                    'Fees': {
                        'model': Fee,
                        'fields': ['pen_num', 'year', 'school_fee', 'concession_reason', 
                                 'school_fee_concession', 'transport_used', 'application_fee', 
                                 'transport_fee', 'transport_fee_concession', 'transport_id', 
                                 'created_at', 'created_by', 'updated_by']
                    },
                    'Fee_Breakdown': {
                        'model': FeeBreakdown,
                        'fields': ['pen_num', 'year', 'fee_type', 'term', 'payment_type', 'paid', 
                                 'due', 'receipt_no', 'fee_paid_date', 'created_at', 'created_by', 
                                 'updated_by']
                    },
                    'Transport': {
                        'model': Transport,
                        'fields': ['transport_id', 'pick_up_point', 'route_number', 'created_at', 
                                 'created_by', 'updated_by']
                    }
                }
                
                backup_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Backup each table
                for sheet_name, config in table_configs.items():
                    try:
                        self._backup_table_to_sheet(sheet_name, config, backup_timestamp)
                        logger.info(f"Successfully backed up {sheet_name}")
                    except Exception as e:
                        logger.error(f"Failed to backup {sheet_name}: {e}")
                
                # Log the backup activity
                self._log_backup_activity(backup_timestamp)
                
                logger.info("Nightly backup completed successfully")
                
            except Exception as e:
                logger.error(f"Nightly backup failed: {e}")
    
    def _backup_table_to_sheet(self, sheet_name: str, config: Dict[str, Any], timestamp: str):
        """Backup a single table to a Google Sheet."""
        try:
            model = config['model']
            fields = config['fields']
            
            # Get all data from the table
            data = model.query.all()
            
            # Try to get existing worksheet or create new one
            try:
                worksheet = self.spreadsheet.worksheet(sheet_name)
                # Clear existing data
                worksheet.clear()
            except gspread.WorksheetNotFound:
                worksheet = self.spreadsheet.add_worksheet(title=sheet_name, rows=1000, cols=20)
            
            if not data:
                # Just add headers if no data
                headers = ['Backup_Timestamp'] + fields
                worksheet.append_row(headers)
                return
            
            # Prepare headers
            headers = ['Backup_Timestamp'] + fields
            
            # Prepare data rows
            rows = []
            for record in data:
                row = [timestamp]
                for field in fields:
                    value = getattr(record, field, '')
                    if value is None:
                        value = ''
                    elif isinstance(value, datetime):
                        value = value.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        value = str(value)
                    row.append(value)
                rows.append(row)
            
            # Write to sheet
            if rows:
                # Add headers first
                worksheet.append_row(headers)
                # Add data in batches to avoid API limits
                batch_size = 100
                for i in range(0, len(rows), batch_size):
                    batch = rows[i:i + batch_size]
                    worksheet.append_rows(batch)
            
            logger.info(f"Backed up {len(rows)} records to {sheet_name}")
            
        except Exception as e:
            logger.error(f"Error backing up {sheet_name}: {e}")
            raise
    
    def _log_backup_activity(self, timestamp: str):
        """Log backup activity to the database."""
        try:
            from school.models import ActivityLog
            from school import db
            
            activity = ActivityLog(
                user_id=None,  # System backup
                action_type='backup',
                entity_type='Database',
                entity_id='ALL_TABLES',
                description=f"Automated nightly backup to Google Sheets completed at {timestamp}",
                ip_address='127.0.0.1',
                user_agent='BackupService'
            )
            db.session.add(activity)
            db.session.commit()
            
        except Exception as e:
            logger.error(f"Failed to log backup activity: {e}")
    
    def manual_backup(self) -> Dict[str, Any]:
        """Trigger a manual backup and return status."""
        if not self.gc or not self.spreadsheet:
            return {
                'success': False,
                'message': 'Google Sheets client not configured'
            }
        
        try:
            self.run_nightly_backup()
            return {
                'success': True,
                'message': 'Manual backup completed successfully'
            }
        except Exception as e:
            logger.error(f"Manual backup failed: {e}")
            return {
                'success': False,
                'message': f'Backup failed: {str(e)}'
            }
