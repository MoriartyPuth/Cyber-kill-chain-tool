from datetime import datetime
import os

from flask import flash, redirect, render_template, request, session, url_for


def register_auth_routes(app, deps):
    db = deps["db"]
    User = deps["User"]
    Simulation = deps["Simulation"]
    AnalyticsReport = deps["AnalyticsReport"]
    ai_enabled = deps["AI_ENABLED"]

    @app.route("/register", methods=["GET", "POST"])
    def register():
        """User registration"""
        if request.method == "POST":
            username = request.form.get("username")
            email = request.form.get("email")
            password = request.form.get("password")

            if not username or not email or not password:
                flash("All fields are required", "error")
                return redirect(url_for("register"))

            if User.query.filter_by(username=username).first():
                flash("Username already exists", "error")
                return redirect(url_for("register"))

            try:
                user = User(
                    username=username,
                    email=email,
                    password_hash=password,
                    budget=int(os.getenv("INITIAL_BUDGET", 5000)),
                )
                db.session.add(user)
                db.session.commit()

                session["user_id"] = user.id
                session["budget"] = user.budget
                flash(f"Welcome {username}!", "success")
                return redirect(url_for("dashboard"))
            except Exception as e:
                db.session.rollback()
                flash(f"Registration error: {str(e)}", "error")
                return redirect(url_for("register"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """User login"""
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            user = User.query.filter_by(username=username).first()

            if user and user.password_hash == password:
                session["user_id"] = user.id
                session["budget"] = user.budget
                user.last_login = datetime.utcnow()
                db.session.commit()
                flash(f"Welcome back, {username}!", "success")
                return redirect(url_for("dashboard"))
            flash("Invalid username or password", "error")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        """User logout"""
        session.clear()
        flash("You have been logged out", "info")
        return redirect(url_for("login"))

    @app.route("/user/profile")
    def user_profile():
        """User profile and statistics"""
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("login"))

        try:
            user = User.query.get(user_id)
            report = AnalyticsReport.query.filter_by(user_id=user_id).first()
            recent_sims = (
                Simulation.query.filter_by(user_id=user_id)
                .order_by(Simulation.created_at.desc())
                .limit(10)
                .all()
            )

            return render_template(
                "profile.html",
                user=user,
                analytics=report,
                recent_simulations=recent_sims,
                ai_enabled=ai_enabled,
            )
        except Exception as e:
            flash(f"Error loading profile: {str(e)}", "error")
            return redirect(url_for("dashboard"))
