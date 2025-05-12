from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, IPAddress, Optional, NumberRange
import re

class LoginForm(FlaskForm):
    """User login form"""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128)])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    """User registration form with security validation"""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[
        DataRequired(), 
        Length(min=8, max=128),
    ])
    password2 = PasswordField(
        'Confirm Password', 
        validators=[DataRequired(), EqualTo('password', message='Passwords must match')]
    )
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        """Validate username for security - prevent injection attacks"""
        # Only allow alphanumeric characters and underscore
        if not re.match(r'^[a-zA-Z0-9_]+$', username.data):
            raise ValidationError('Username can only contain letters, numbers, and underscores')
            
    def validate_password(self, password):
        """Validate password strength"""
        # Check password complexity requirements
        if not re.search(r'[A-Z]', password.data):
            raise ValidationError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', password.data):
            raise ValidationError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', password.data):
            raise ValidationError('Password must contain at least one number')
        if not re.search(r'[^A-Za-z0-9]', password.data):
            raise ValidationError('Password must contain at least one special character')

class ProxyForm(FlaskForm):
    """Form for adding a proxy manually"""
    host = StringField('Proxy Host/IP', validators=[
        DataRequired(),
        # Use custom validation for hostname/IP validation
    ])
    port = IntegerField('Port', validators=[
        DataRequired(),
        NumberRange(min=1, max=65535, message='Port must be between 1 and 65535')
    ])
    submit = SubmitField('Add Proxy')
    
    def validate_host(self, host):
        """Validate host is either a valid IP or hostname"""
        # IP address validation
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        # Hostname validation (simplified)
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not (re.match(ip_pattern, host.data) or re.match(hostname_pattern, host.data)):
            raise ValidationError('Invalid IP address or hostname format')

class ScannerForm(FlaskForm):
    """Form for scanner settings"""
    batch_size = IntegerField('Batch Size', validators=[
        DataRequired(),
        NumberRange(min=10, max=1000, message='Batch size must be between 10 and 1000')
    ])
    max_conns = IntegerField('Max Connections', validators=[
        DataRequired(),
        NumberRange(min=5, max=200, message='Max connections must be between 5 and 200')
    ])
    verbose = BooleanField('Verbose Mode')
    submit = SubmitField('Start Scanner')