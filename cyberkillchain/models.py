from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.dialects.sqlite import JSON

db = SQLAlchemy()

class User(db.Model):
    """User account and profile information"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="viewer", index=True)
    budget = db.Column(db.Integer, default=5000)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    simulations = db.relationship('Simulation', backref='user', lazy=True, cascade='all, delete-orphan')
    upgrades_purchased = db.relationship('UpgradePurchase', backref='user', lazy=True, cascade='all, delete-orphan')
    analytics_reports = db.relationship('AnalyticsReport', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'


class Simulation(db.Model):
    """Individual simulation run data"""
    __tablename__ = 'simulations'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    attack_type = db.Column(db.String(50), nullable=False, index=True)
    detection_score = db.Column(db.Integer, nullable=False)
    
    # Store event details as JSON
    events = db.Column(JSON, nullable=False)  # List of detection events
    weakest_stages = db.Column(JSON)  # Stages that were missed
    tags = db.Column(JSON, default=list)
    variant = db.Column(db.String(20), default="standard")
    
    # AI-generated content
    threat_narrative = db.Column(db.Text)  # AI-generated threat description
    ai_recommendations = db.Column(JSON)  # AI-generated recommendations
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Simulation {self.id}: {self.attack_type} - {self.detection_score}%>'


class UpgradePurchase(db.Model):
    """Track all upgrade purchases"""
    __tablename__ = 'upgrade_purchases'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    upgrade_name = db.Column(db.String(100), nullable=False)
    cost = db.Column(db.Integer, nullable=False)
    roi_multiplier = db.Column(db.Float, default=1.0)
    stage = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f'<UpgradePurchase {self.upgrade_name}>'


class AnalyticsReport(db.Model):
    """Aggregated analytics and performance metrics"""
    __tablename__ = 'analytics_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Overall metrics
    total_simulations = db.Column(db.Integer, default=0)
    average_score = db.Column(db.Float, default=0.0)
    max_score = db.Column(db.Integer, default=0)
    min_score = db.Column(db.Integer, default=0)
    
    # Attack breakdown
    attack_breakdown = db.Column(JSON)  # {"Phishing": 75, "Malware": 80, ...}
    
    # Defense effectiveness
    strongest_defense = db.Column(db.String(50))
    weakest_defense = db.Column(db.String(50))
    
    # Investment analysis
    total_invested = db.Column(db.Integer, default=0)
    roi_analysis = db.Column(JSON)  # ROI data for each upgrade
    
    # AI insights
    ai_insights = db.Column(db.Text)  # AI-generated strategic insights
    
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<AnalyticsReport User{self.user_id}>'


class AIInsight(db.Model):
    """Store AI-generated insights and threat intelligence"""
    __tablename__ = 'ai_insights'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    insight_type = db.Column(db.String(50), nullable=False)  # 'threat_narrative', 'recommendation', 'strategy'
    content = db.Column(db.Text, nullable=False)
    related_attack = db.Column(db.String(50))
    related_stage = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f'<AIInsight {self.insight_type}>'


class SavedSearch(db.Model):
    """Saved search queries per user"""
    __tablename__ = 'saved_searches'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    query_text = db.Column(db.String(200), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class SimulationPreset(db.Model):
    """Reusable simulation presets"""
    __tablename__ = 'simulation_presets'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    attack_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class SimulationSchedule(db.Model):
    """Simple interval-based schedule for presets"""
    __tablename__ = 'simulation_schedules'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    preset_id = db.Column(db.Integer, db.ForeignKey('simulation_presets.id'), nullable=False, index=True)
    interval_minutes = db.Column(db.Integer, default=60)
    last_run_at = db.Column(db.DateTime)
    enabled = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class Case(db.Model):
    """Case management for simulations"""
    __tablename__ = 'cases'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    simulation_id = db.Column(db.Integer, db.ForeignKey('simulations.id'))
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default="Open", index=True)
    severity = db.Column(db.String(20), default="Low", index=True)
    sla_hours = db.Column(db.Integer, default=48)
    escalated = db.Column(db.Boolean, default=False, index=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CaseNote(db.Model):
    """Notes for cases"""
    __tablename__ = 'case_notes'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    note = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class CaseAttachment(db.Model):
    """Evidence attachments for cases"""
    __tablename__ = 'case_attachments'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    filename = db.Column(db.String(200), nullable=False)
    stored_path = db.Column(db.String(300), nullable=False)
    content_type = db.Column(db.String(100))
    size_bytes = db.Column(db.Integer)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class CaseEvent(db.Model):
    """Chain-of-custody timeline events"""
    __tablename__ = 'case_events'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(120), nullable=False)
    meta = db.Column(JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class CaseChecklistItem(db.Model):
    """Compliance checklist items per case"""
    __tablename__ = 'case_checklist_items'

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False, index=True)
    framework = db.Column(db.String(20), nullable=False)  # NIST/ISO
    item = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="open")  # open/done
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AuditLog(db.Model):
    """Audit trail for admin and analyst actions"""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    action = db.Column(db.String(120), nullable=False)
    meta = db.Column(JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class RetentionPolicy(db.Model):
    """Retention settings for data cleanup"""
    __tablename__ = 'retention_policies'

    id = db.Column(db.Integer, primary_key=True)
    simulations_days = db.Column(db.Integer, default=90)
    audit_days = db.Column(db.Integer, default=180)
    live_logs_days = db.Column(db.Integer, default=30)
    enabled = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ThreatSignature(db.Model):
    """Learned threat pattern signatures"""
    __tablename__ = 'threat_signatures'

    id = db.Column(db.Integer, primary_key=True)
    fingerprint = db.Column(db.String(64), unique=True, nullable=False, index=True)
    label = db.Column(db.String(120))
    count = db.Column(db.Integer, default=1)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    status = db.Column(db.String(20), default="new", index=True)  # new/reviewed/ignored


class ThreatDiscovery(db.Model):
    """Recorded discoveries of new or rare threats"""
    __tablename__ = 'threat_discoveries'

    id = db.Column(db.Integer, primary_key=True)
    signature_id = db.Column(db.Integer, db.ForeignKey('threat_signatures.id'), nullable=False, index=True)
    source = db.Column(db.String(20), default="log")  # log/simulation
    sample = db.Column(JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class ThreatSummary(db.Model):
    """Periodic summary of discovered threats"""
    __tablename__ = 'threat_summaries'

    id = db.Column(db.Integer, primary_key=True)
    summary = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class ThreatAdvisory(db.Model):
    """Actionable advisory generated from recurring threat patterns."""
    __tablename__ = 'threat_advisories'

    id = db.Column(db.Integer, primary_key=True)
    advisory_key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    title = db.Column(db.String(160), nullable=False)
    priority = db.Column(db.String(20), default="medium", index=True)  # critical/high/medium
    summary = db.Column(db.Text, nullable=False)
    recommended_actions = db.Column(JSON)
    signal_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default="open", index=True)  # open/applied/dismissed
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ThreatSettings(db.Model):
    """Threat discovery tuning"""
    __tablename__ = 'threat_settings'

    id = db.Column(db.Integer, primary_key=True)
    anomaly_threshold = db.Column(db.Integer, default=2)  # flag if seen <= threshold
    auto_case = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class UserWidget(db.Model):
    """Dashboard widget preferences"""
    __tablename__ = 'user_widgets'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    widget_key = db.Column(db.String(50), nullable=False, index=True)
    enabled = db.Column(db.Boolean, default=True)


class Indicator(db.Model):
    """Threat intel indicators (e.g., IPs)"""
    __tablename__ = 'indicators'

    id = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(20), nullable=False, index=True)
    value = db.Column(db.String(80), nullable=False, index=True)
    enrichment = db.Column(JSON)
    confidence = db.Column(db.Float, default=0.5)
    status = db.Column(db.String(20), default="new", index=True)  # new/validated/false_positive/expired
    source = db.Column(db.String(30), default="log")
    last_seen_attack = db.Column(db.String(50))
    last_seen_stage = db.Column(db.String(50))
    count = db.Column(db.Integer, default=1)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    expires_at = db.Column(db.DateTime)


class IndicatorRelation(db.Model):
    """Links indicators to related entities (cases, sims, signatures)"""
    __tablename__ = 'indicator_relations'

    id = db.Column(db.Integer, primary_key=True)
    indicator_id = db.Column(db.Integer, db.ForeignKey('indicators.id'), nullable=False, index=True)
    relation_type = db.Column(db.String(30), nullable=False)  # case/simulation/signature/log
    relation_id = db.Column(db.String(120), nullable=False)
    meta = db.Column(JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class AlertRule(db.Model):
    """Server-side alert rules for live monitoring"""
    __tablename__ = 'alert_rules'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True, nullable=True)
    name = db.Column(db.String(80), nullable=False)
    enabled = db.Column(db.Boolean, default=True, index=True)
    attack_type = db.Column(db.String(50))
    stage = db.Column(db.String(50))
    status = db.Column(db.String(20), default="Missed")
    severity_threshold = db.Column(db.String(20), default="medium")
    auto_case = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class LiveFilter(db.Model):
    """Saved live feed filters"""
    __tablename__ = 'live_filters'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    filters = db.Column(JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class LiveLog(db.Model):
    """Persisted live log payloads for replay/history"""
    __tablename__ = 'live_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    raw_log = db.Column(JSON, nullable=False)
    mapped_event = db.Column(JSON)
    payload = db.Column(JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class FeatureModuleSetting(db.Model):
    """Per-user settings for feature modules"""
    __tablename__ = 'feature_module_settings'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    module_id = db.Column(db.String(80), nullable=False, index=True)
    settings = db.Column(JSON, nullable=False, default=dict)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)
