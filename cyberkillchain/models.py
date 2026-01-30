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
