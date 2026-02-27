from sqlalchemy import text


def init_migration_support(app, db):
    """Initialize Flask-Migrate when available; no-op fallback when not installed."""
    try:
        from flask_migrate import Migrate
    except Exception:
        return None
    return Migrate(app, db)


def ensure_schema(app, db):
    """Lightweight SQLite migrations for new columns/tables."""
    if not app.config.get('SQLALCHEMY_DATABASE_URI', '').startswith('sqlite'):
        return

    def _table_columns(table):
        rows = db.session.execute(text(f"PRAGMA table_info({table})")).fetchall()
        return {r[1] for r in rows}

    # Add missing columns
    try:
        user_cols = _table_columns("users")
        if "role" not in user_cols:
            db.session.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'viewer'"))

        sim_cols = _table_columns("simulations")
        if "tags" not in sim_cols:
            db.session.execute(text("ALTER TABLE simulations ADD COLUMN tags JSON"))
        if "variant" not in sim_cols:
            db.session.execute(text("ALTER TABLE simulations ADD COLUMN variant VARCHAR(20)"))

        # Saved searches table & column migration
        tables = {r[0] for r in db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        if "saved_searches" not in tables:
            db.session.execute(text(
                "CREATE TABLE saved_searches ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "name VARCHAR(80) NOT NULL, "
                "query_text VARCHAR(200) NOT NULL, "
                "created_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))
        else:
            ss_cols = _table_columns("saved_searches")
            if "query_text" not in ss_cols:
                db.session.execute(text("ALTER TABLE saved_searches ADD COLUMN query_text VARCHAR(200)"))
                if "query" in ss_cols:
                    db.session.execute(text("UPDATE saved_searches SET query_text = query WHERE query_text IS NULL"))

        if "simulation_presets" not in tables:
            db.session.execute(text(
                "CREATE TABLE simulation_presets ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "name VARCHAR(80) NOT NULL, "
                "attack_type VARCHAR(50) NOT NULL, "
                "created_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))

        if "simulation_schedules" not in tables:
            db.session.execute(text(
                "CREATE TABLE simulation_schedules ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "preset_id INTEGER NOT NULL, "
                "interval_minutes INTEGER DEFAULT 60, "
                "last_run_at DATETIME, "
                "enabled BOOLEAN DEFAULT 1, "
                "created_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id), "
                "FOREIGN KEY(preset_id) REFERENCES simulation_presets(id))"
            ))

        if "cases" not in tables:
            db.session.execute(text(
                "CREATE TABLE cases ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "simulation_id INTEGER, "
                "title VARCHAR(120) NOT NULL, "
                "description TEXT, "
                "status VARCHAR(20) DEFAULT 'Open', "
                "severity VARCHAR(20) DEFAULT 'Low', "
                "sla_hours INTEGER DEFAULT 48, "
                "escalated BOOLEAN DEFAULT 0, "
                "assignee_id INTEGER, "
                "created_at DATETIME, "
                "updated_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id), "
                "FOREIGN KEY(simulation_id) REFERENCES simulations(id), "
                "FOREIGN KEY(assignee_id) REFERENCES users(id))"
            ))
        else:
            case_cols = _table_columns("cases")
            if "sla_hours" not in case_cols:
                db.session.execute(text("ALTER TABLE cases ADD COLUMN sla_hours INTEGER DEFAULT 48"))
            if "escalated" not in case_cols:
                db.session.execute(text("ALTER TABLE cases ADD COLUMN escalated BOOLEAN DEFAULT 0"))

        if "case_notes" not in tables:
            db.session.execute(text(
                "CREATE TABLE case_notes ("
                "id INTEGER PRIMARY KEY, "
                "case_id INTEGER NOT NULL, "
                "author_id INTEGER NOT NULL, "
                "note TEXT NOT NULL, "
                "created_at DATETIME, "
                "FOREIGN KEY(case_id) REFERENCES cases(id), "
                "FOREIGN KEY(author_id) REFERENCES users(id))"
            ))

        if "case_attachments" not in tables:
            db.session.execute(text(
                "CREATE TABLE case_attachments ("
                "id INTEGER PRIMARY KEY, "
                "case_id INTEGER NOT NULL, "
                "filename VARCHAR(200) NOT NULL, "
                "stored_path VARCHAR(300) NOT NULL, "
                "content_type VARCHAR(100), "
                "size_bytes INTEGER, "
                "uploaded_by INTEGER, "
                "created_at DATETIME, "
                "FOREIGN KEY(case_id) REFERENCES cases(id), "
                "FOREIGN KEY(uploaded_by) REFERENCES users(id))"
            ))

        if "case_events" not in tables:
            db.session.execute(text(
                "CREATE TABLE case_events ("
                "id INTEGER PRIMARY KEY, "
                "case_id INTEGER NOT NULL, "
                "actor_id INTEGER, "
                "action VARCHAR(120) NOT NULL, "
                "meta JSON, "
                "created_at DATETIME, "
                "FOREIGN KEY(case_id) REFERENCES cases(id), "
                "FOREIGN KEY(actor_id) REFERENCES users(id))"
            ))

        if "case_checklist_items" not in tables:
            db.session.execute(text(
                "CREATE TABLE case_checklist_items ("
                "id INTEGER PRIMARY KEY, "
                "case_id INTEGER NOT NULL, "
                "framework VARCHAR(20) NOT NULL, "
                "item VARCHAR(200) NOT NULL, "
                "status VARCHAR(20) DEFAULT 'open', "
                "updated_at DATETIME, "
                "FOREIGN KEY(case_id) REFERENCES cases(id))"
            ))

        if "audit_logs" not in tables:
            db.session.execute(text(
                "CREATE TABLE audit_logs ("
                "id INTEGER PRIMARY KEY, "
                "actor_id INTEGER, "
                "action VARCHAR(120) NOT NULL, "
                "meta JSON, "
                "created_at DATETIME, "
                "FOREIGN KEY(actor_id) REFERENCES users(id))"
            ))

        if "retention_policies" not in tables:
            db.session.execute(text(
                "CREATE TABLE retention_policies ("
                "id INTEGER PRIMARY KEY, "
                "simulations_days INTEGER DEFAULT 90, "
                "audit_days INTEGER DEFAULT 180, "
                "live_logs_days INTEGER DEFAULT 30, "
                "enabled BOOLEAN DEFAULT 1, "
                "updated_at DATETIME)"
            ))
        else:
            retention_cols = _table_columns("retention_policies")
            if "live_logs_days" not in retention_cols:
                db.session.execute(text("ALTER TABLE retention_policies ADD COLUMN live_logs_days INTEGER DEFAULT 30"))

        if "threat_signatures" not in tables:
            db.session.execute(text(
                "CREATE TABLE threat_signatures ("
                "id INTEGER PRIMARY KEY, "
                "fingerprint VARCHAR(64) UNIQUE NOT NULL, "
                "label VARCHAR(120), "
                "count INTEGER DEFAULT 1, "
                "first_seen DATETIME, "
                "last_seen DATETIME, "
                "status VARCHAR(20) DEFAULT 'new')"
            ))

        if "threat_discoveries" not in tables:
            db.session.execute(text(
                "CREATE TABLE threat_discoveries ("
                "id INTEGER PRIMARY KEY, "
                "signature_id INTEGER NOT NULL, "
                "source VARCHAR(20), "
                "sample JSON, "
                "created_at DATETIME, "
                "FOREIGN KEY(signature_id) REFERENCES threat_signatures(id))"
            ))

        if "threat_summaries" not in tables:
            db.session.execute(text(
                "CREATE TABLE threat_summaries ("
                "id INTEGER PRIMARY KEY, "
                "summary TEXT NOT NULL, "
                "created_at DATETIME)"
            ))

        if "threat_advisories" not in tables:
            db.session.execute(text(
                "CREATE TABLE threat_advisories ("
                "id INTEGER PRIMARY KEY, "
                "advisory_key VARCHAR(64) UNIQUE NOT NULL, "
                "title VARCHAR(160) NOT NULL, "
                "priority VARCHAR(20) DEFAULT 'medium', "
                "summary TEXT NOT NULL, "
                "recommended_actions JSON, "
                "signal_count INTEGER DEFAULT 0, "
                "status VARCHAR(20) DEFAULT 'open', "
                "created_at DATETIME, "
                "updated_at DATETIME)"
            ))

        if "threat_settings" not in tables:
            db.session.execute(text(
                "CREATE TABLE threat_settings ("
                "id INTEGER PRIMARY KEY, "
                "anomaly_threshold INTEGER DEFAULT 2, "
                "auto_case BOOLEAN DEFAULT 1, "
                "updated_at DATETIME)"
            ))

        if "user_widgets" not in tables:
            db.session.execute(text(
                "CREATE TABLE user_widgets ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "widget_key VARCHAR(50) NOT NULL, "
                "enabled BOOLEAN DEFAULT 1, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))

        if "indicators" not in tables:
            db.session.execute(text(
                "CREATE TABLE indicators ("
                "id INTEGER PRIMARY KEY, "
                "indicator_type VARCHAR(20) NOT NULL, "
                "value VARCHAR(80) NOT NULL, "
                "enrichment JSON, "
                "confidence FLOAT DEFAULT 0.5, "
                "status VARCHAR(20) DEFAULT 'new', "
                "source VARCHAR(30) DEFAULT 'log', "
                "last_seen_attack VARCHAR(50), "
                "last_seen_stage VARCHAR(50), "
                "count INTEGER DEFAULT 1, "
                "first_seen DATETIME, "
                "last_seen DATETIME, "
                "expires_at DATETIME)"
            ))
        else:
            ind_cols = _table_columns("indicators")
            if "confidence" not in ind_cols:
                db.session.execute(text("ALTER TABLE indicators ADD COLUMN confidence FLOAT DEFAULT 0.5"))
            if "status" not in ind_cols:
                db.session.execute(text("ALTER TABLE indicators ADD COLUMN status VARCHAR(20) DEFAULT 'new'"))
            if "source" not in ind_cols:
                db.session.execute(text("ALTER TABLE indicators ADD COLUMN source VARCHAR(30) DEFAULT 'log'"))
            if "last_seen_attack" not in ind_cols:
                db.session.execute(text("ALTER TABLE indicators ADD COLUMN last_seen_attack VARCHAR(50)"))
            if "last_seen_stage" not in ind_cols:
                db.session.execute(text("ALTER TABLE indicators ADD COLUMN last_seen_stage VARCHAR(50)"))
            if "expires_at" not in ind_cols:
                db.session.execute(text("ALTER TABLE indicators ADD COLUMN expires_at DATETIME"))

        if "indicator_relations" not in tables:
            db.session.execute(text(
                "CREATE TABLE indicator_relations ("
                "id INTEGER PRIMARY KEY, "
                "indicator_id INTEGER NOT NULL, "
                "relation_type VARCHAR(30) NOT NULL, "
                "relation_id VARCHAR(120) NOT NULL, "
                "meta JSON, "
                "created_at DATETIME, "
                "FOREIGN KEY(indicator_id) REFERENCES indicators(id))"
            ))

        if "alert_rules" not in tables:
            db.session.execute(text(
                "CREATE TABLE alert_rules ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER, "
                "name VARCHAR(80) NOT NULL, "
                "enabled BOOLEAN DEFAULT 1, "
                "attack_type VARCHAR(50), "
                "stage VARCHAR(50), "
                "status VARCHAR(20) DEFAULT 'Missed', "
                "severity_threshold VARCHAR(20) DEFAULT 'medium', "
                "auto_case BOOLEAN DEFAULT 0, "
                "created_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))

        if "live_filters" not in tables:
            db.session.execute(text(
                "CREATE TABLE live_filters ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "name VARCHAR(80) NOT NULL, "
                "filters JSON NOT NULL, "
                "created_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))

        if "live_logs" not in tables:
            db.session.execute(text(
                "CREATE TABLE live_logs ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER, "
                "raw_log JSON NOT NULL, "
                "mapped_event JSON, "
                "payload JSON, "
                "created_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))

        if "feature_module_settings" not in tables:
            db.session.execute(text(
                "CREATE TABLE feature_module_settings ("
                "id INTEGER PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "module_id VARCHAR(80) NOT NULL, "
                "settings JSON NOT NULL, "
                "updated_at DATETIME, "
                "FOREIGN KEY(user_id) REFERENCES users(id))"
            ))

        db.session.commit()
    except Exception as e:
        print(f"Schema ensure failed: {e}")
        db.session.rollback()

