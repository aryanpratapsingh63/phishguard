"""
PHISHGUARD – Phishing URL Detection & Risk Analysis System
Main Flask Application Entry Point.
"""

import os
import json
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    Response,
)

from config import Config
from analyzer import parse_url, extract_features, evaluate_url_risk
from database import (
    init_db,
    save_scan,
    get_recent_scans,
    get_scan_by_id,
    clear_history,
    delete_scan,
    get_scan_stats,
)
from ml import (
    train_and_evaluate_model,
    load_cached_metrics,
    save_evaluation_metrics,
)


def create_app(config_class=Config) -> Flask:
    """Application factory for PHISHGUARD."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize SQLite database schema
    init_db(app.config["DATABASE_PATH"])

    # ---------------------------------------------------------
    # Route: Home Page / URL Analyzer Dashboard
    # ---------------------------------------------------------
    @app.route("/", methods=["GET"])
    def index():
        return render_template(
            "index.html",
            sample_presets=Config.SAMPLE_URLS,
        )

    # ---------------------------------------------------------
    # Route: Analyze URL Submission
    # ---------------------------------------------------------
    @app.route("/analyze", methods=["GET", "POST"])
    def analyze():
        if request.method == "POST":
            raw_url = request.form.get("url", "")
        else:
            raw_url = request.args.get("url", "")

        # 1. Validation & Safe Parsing (Strictly local, no network requests)
        parsed = parse_url(raw_url, max_length=app.config["MAX_URL_LENGTH"])
        if not parsed.is_valid:
            flash(parsed.error_message or "Invalid URL input provided.", "error")
            return redirect(url_for("index"))

        # 2. Extract Explainable Features
        features = extract_features(parsed)

        # 3. Evaluate Rule-Based Risk Engine
        report = evaluate_url_risk(parsed, features)

        # 4. Save to SQLite Scan Audit Log
        try:
            summary_titles = ", ".join([ind.title for ind in report.indicators[:3]])
            save_scan(
                url=parsed.original_url,
                normalized_url=parsed.normalized_url,
                hostname=parsed.hostname,
                risk_score=report.score,
                classification=report.classification,
                indicators_count=len(report.indicators),
                indicators_summary=summary_titles,
                db_path=app.config["DATABASE_PATH"],
            )
        except Exception as e:
            # Audit logging failure should not prevent user from seeing scan report
            app.logger.warning(f"Failed to record scan audit in SQLite: {e}")

        return render_template("result.html", report=report)

    # ---------------------------------------------------------
    # Route: RESTful JSON API for Programmatic Inspection
    # ---------------------------------------------------------
    @app.route("/api/analyze", methods=["GET", "POST"])
    def api_analyze():
        """
        API endpoint returning structured risk analysis JSON.
        Accepts ?url= query string or JSON payload {"url": "..."}.
        """
        if request.is_json:
            data = request.get_json(silent=True) or {}
            raw_url = data.get("url", "")
        elif request.method == "POST":
            raw_url = request.form.get("url", "")
        else:
            raw_url = request.args.get("url", "")

        parsed = parse_url(raw_url, max_length=app.config["MAX_URL_LENGTH"])
        if not parsed.is_valid:
            return jsonify({
                "status": "error",
                "is_valid": False,
                "error_message": parsed.error_message
            }), 400

        features = extract_features(parsed)
        report = evaluate_url_risk(parsed, features)

        # Record scan
        try:
            summary_titles = ", ".join([ind.title for ind in report.indicators[:3]])
            save_scan(
                url=parsed.original_url,
                normalized_url=parsed.normalized_url,
                hostname=parsed.hostname,
                risk_score=report.score,
                classification=report.classification,
                indicators_count=len(report.indicators),
                indicators_summary=summary_titles,
                db_path=app.config["DATABASE_PATH"],
            )
        except Exception as e:
            app.logger.warning(f"API scan history save error: {e}")

        return jsonify({
            "status": "success",
            "is_valid": True,
            "url": parsed.original_url,
            "normalized_url": parsed.normalized_url,
            "hostname": parsed.hostname,
            "risk_score": report.score,
            "classification": report.classification,
            "summary_verdict": report.summary_verdict,
            "indicators": [ind.to_dict() for ind in report.indicators],
            "recommendations": report.recommendations,
            "features": features.to_dict()
        })

    # ---------------------------------------------------------
    # Route: Scan History & Audit Trail
    # ---------------------------------------------------------
    @app.route("/history", methods=["GET"])
    def history():
        query = request.args.get("q", "")
        scans = get_recent_scans(limit=100, search_query=query, db_path=app.config["DATABASE_PATH"])
        stats = get_scan_stats(db_path=app.config["DATABASE_PATH"])
        return render_template("history.html", scans=scans, stats=stats, query=query)

    # ---------------------------------------------------------
    # Route: Clear Entire Scan History
    # ---------------------------------------------------------
    @app.route("/history/clear", methods=["POST"])
    def clear_all_history():
        deleted = clear_history(db_path=app.config["DATABASE_PATH"])
        flash(f"Scan history successfully cleared. {deleted} records removed.", "success")
        return redirect(url_for("history"))

    # ---------------------------------------------------------
    # Route: Delete Single Scan Record
    # ---------------------------------------------------------
    @app.route("/history/delete/<int:scan_id>", methods=["POST"])
    def delete_history_item(scan_id: int):
        success = delete_scan(scan_id, db_path=app.config["DATABASE_PATH"])
        if success:
            flash("Audit record deleted.", "info")
        else:
            flash("Record not found.", "warning")
        return redirect(url_for("history"))

    # ---------------------------------------------------------
    # Route: Export Scan History as JSON
    # ---------------------------------------------------------
    @app.route("/history/export", methods=["GET"])
    def export_history_json():
        scans = get_recent_scans(limit=1000, db_path=app.config["DATABASE_PATH"])
        json_data = json.dumps(scans, indent=2)
        return Response(
            json_data,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment;filename=phishguard_scans.json"}
        )

    # ---------------------------------------------------------
    # Route: Machine Learning Evaluation Dashboard
    # ---------------------------------------------------------
    @app.route("/ml", methods=["GET"])
    def ml_dashboard():
        metrics = load_cached_metrics()
        return render_template("ml_dashboard.html", metrics=metrics)

    # ---------------------------------------------------------
    # Route: Re-Train / Re-Evaluate ML Benchmark
    # ---------------------------------------------------------
    @app.route("/ml/train", methods=["POST"])
    def run_ml_evaluation():
        metrics = train_and_evaluate_model()
        save_evaluation_metrics(metrics)
        flash("Machine learning benchmark model re-trained and re-evaluated successfully on test partition.", "success")
        return redirect(url_for("ml_dashboard"))

    # ---------------------------------------------------------
    # Defensive Error Handlers
    # ---------------------------------------------------------
    @app.errorhandler(400)
    def bad_request(error):
        return render_template(
            "error.html",
            error_code=400,
            error_title="Malformed Request",
            error_message="The input request could not be processed due to invalid parameters or malformed characters.",
            debug_hint=str(error)
        ), 400

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template(
            "error.html",
            error_code=404,
            error_title="Resource Not Found",
            error_message="The requested endpoint or URL inspection report could not be found.",
            debug_hint="Check the navigation menu or return to the main dashboard."
        ), 404

    @app.errorhandler(500)
    def internal_error(error):
        return render_template(
            "error.html",
            error_code=500,
            error_title="Security Engine Exception",
            error_message="An unexpected condition occurred within the heuristic processing engine. No external connections were attempted.",
            debug_hint="Check server terminal logs for traceback details."
        ), 500

    return app


# Main application instance for WSGI servers
app = create_app()

if __name__ == "__main__":
    # College-ready friendly console output
    print("=" * 65)
    print(" 🛡️  PHISHGUARD: Phishing URL Detection & Risk Analysis System")
    print(" 🔒  Defensive Cybersecurity Local Inspection Server")
    print(" 🚀  Starting web application on http://127.0.0.1:5000")
    print("=" * 65)
    app.run(host="127.0.0.1", port=5000, debug=True)
