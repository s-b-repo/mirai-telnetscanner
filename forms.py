"""
Form classes for the Telnet Scanner application
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, IPAddress, NumberRange, ValidationError, Optional
import ipaddress

class LoginForm(FlaskForm):
    """User login form"""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    """User registration form (admin only can create users)"""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    is_admin = BooleanField('Administrator')
    submit = SubmitField('Register User')

class ProxyForm(FlaskForm):
    """Form for adding a new proxy"""
    host = StringField('Host', validators=[DataRequired(), IPAddress(ipv4=True, ipv6=True)])
    port = IntegerField('Port', validators=[DataRequired(), NumberRange(min=1, max=65535)])
    submit = SubmitField('Add Proxy')

class ScannerForm(FlaskForm):
    """Form for scanner settings and control"""
    batch_size = IntegerField('Batch Size', validators=[NumberRange(min=10, max=1000)], default=200)
    max_concurrent = IntegerField('Max Concurrent Connections', validators=[NumberRange(min=10, max=200)], default=50)
    use_proxies = BooleanField('Use Proxies', default=True)
    include_ports = StringField('Ports to Scan (comma separated)', default="23,2323")
    
    def validate_include_ports(self, field):
        """Validate that the ports are valid numbers"""
        try:
            ports = [int(p.strip()) for p in field.data.split(',') if p.strip()]
            for port in ports:
                if port < 1 or port > 65535:
                    raise ValidationError("Ports must be between 1 and 65535")
        except ValueError:
            raise ValidationError("Ports must be valid numbers separated by commas")
    
    submit = SubmitField('Start Scanner')

class CredentialForm(FlaskForm):
    """Form for adding a new credential"""
    username = StringField('Username', validators=[DataRequired(), Length(max=64)])
    password = StringField('Password', validators=[DataRequired(), Length(max=64)])
    submit = SubmitField('Add Credential')

class BatchCredentialForm(FlaskForm):
    """Form for adding multiple credentials"""
    credentials = TextAreaField('Credentials (username:password, one per line)', validators=[DataRequired()])
    submit = SubmitField('Add Credentials')

class IPRangeForm(FlaskForm):
    """Form for adding a specific IP range to scan"""
    ip_range = StringField('IP Range (CIDR notation)', validators=[DataRequired()])
    
    def validate_ip_range(self, field):
        """Validate CIDR notation"""
        try:
            ipaddress.ip_network(field.data, strict=False)
        except ValueError:
            raise ValidationError("Invalid CIDR notation, e.g., 192.168.1.0/24")
    
    submit = SubmitField('Add Range')

class SettingsForm(FlaskForm):
    """Form for application settings"""
    proxy_refresh_interval = IntegerField('Proxy Refresh Interval (seconds)', 
                                        validators=[NumberRange(min=60, max=3600)], 
                                        default=300)
    telnet_connect_timeout = IntegerField('Telnet Connect Timeout (seconds)', 
                                         validators=[NumberRange(min=1, max=30)], 
                                         default=5)
    telnet_login_timeout = IntegerField('Telnet Login Timeout (seconds)', 
                                       validators=[NumberRange(min=1, max=30)], 
                                       default=6)
    scan_batch_delay = IntegerField('Delay Between Batches (seconds)', 
                                   validators=[NumberRange(min=0, max=60)], 
                                   default=1)
    submit = SubmitField('Save Settings')

class ChangePasswordForm(FlaskForm):
    """Form for changing user password"""
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

class ImportProxiesForm(FlaskForm):
    """Form for importing proxies from text"""
    proxies = TextAreaField('Proxies (host:port, one per line)', validators=[DataRequired()])
    submit = SubmitField('Import Proxies')
