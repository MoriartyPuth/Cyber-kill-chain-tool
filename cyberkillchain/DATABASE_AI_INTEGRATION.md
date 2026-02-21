# Database & AI Integration Guide

## Overview
Your Cyber Kill Chain Simulator now includes:
- **SQLite Database** for persistent user data and simulation history
- **OpenAI Integration** for AI-powered threat analysis and recommendations
- **User Authentication** system for multi-user support
- **Analytics Dashboard** backed by database queries

---

## 📦 Installation Complete

### Installed Packages
- `Flask-SQLAlchemy` - ORM for database management
- `python-dotenv` - Environment variable management
- `openai` - OpenAI API client

### New Files Created
1. **models.py** - SQLAlchemy database models
2. **ai_advisor.py** - AI-powered security advisor service
3. **.env** - Environment configuration file
4. **Templates/login.html** - User login page
5. **Templates/register.html** - User registration page
6. **Templates/profile.html** - User profile and statistics

---

## 🗄️ Database Schema

### Tables
1. **users** - User accounts
   - username, email, password_hash
   - budget, created_at, last_login
   
2. **simulations** - Simulation runs
   - user_id, attack_type
   - detection_score, events, weakest_stages
   - threat_narrative, ai_recommendations
   - created_at, updated_at
   
3. **upgrade_purchases** - Upgrade transaction history
   - user_id, upgrade_name, cost, roi_multiplier
   - stage, quantity, purchase_date
   
4. **analytics_reports** - Aggregated user statistics
   - user_id, total_simulations, average_score
   - attack_breakdown, defense analysis
   - ai_insights, roi_analysis
   
5. **ai_insights** - Stored AI-generated insights
   - user_id, insight_type, content
   - related_attack, related_stage

---

## 🤖 AI Integration Setup

### Enable OpenAI Features
1. Get your API key: https://platform.openai.com/api-keys
2. Open `.env` file in the project root
3. Add your key:
   ```
   OPENAI_API_KEY=sk-your-api-key-here
   ```
4. Restart the application

### AI-Powered Features
Once configured, the following features activate:

#### 1. **Threat Narratives**
- AI generates realistic threat descriptions for each simulation
- Explains attack flow and detection outcomes
- Stored in simulation records for later review

#### 2. **Intelligent Recommendations**
- AI analyzes weakest defense stages
- Suggests specific upgrade purchases
- Provides priority levels (critical/high/medium)
- Includes strategic improvement actions

#### 3. **Strategic Insights**
- Analyzes overall defense posture
- Identifies strengths and gaps
- Recommends next priorities
- Generated after 3+ simulations

#### 4. **Attack Analysis**
- Deep insights into specific attack types
- How attackers exploit weaknesses
- Tactical briefings for each threat vector

#### 5. **Upgrade Optimization**
- AI suggests optimal budget allocation
- Calculates expected improvements
- Considers historical performance data

---

## 🔐 User Authentication System

### Public Routes (No Login Required)
- `/register` - Create new account
- `/login` - Sign in to existing account

### Protected Routes (Login Required)
- `/` - Dashboard
- `/simulate` - Run simulations
- `/upgrade` - Purchase upgrades
- `/user/profile` - View statistics
- `/logout` - Sign out

### Default Guest Mode
- Users can interact without logging in (session-based)
- To persist data, users must create an account

---

## 💾 Database Location
- **File**: `cyber_killchain.db`
- **Location**: Project root directory
- **Type**: SQLite (no external server needed)
- **Auto-created**: Yes, on first run

---

## 📊 New Features

### User Profile Page (`/user/profile`)
- **Account Information**: Username, email, budget
- **Performance Metrics**: Total simulations, average score, best score
- **Attack Breakdown Chart**: Defense effectiveness by attack type
- **Defense Summary**: Strongest/weakest defenses identified
- **Recent Simulations**: Last 10 simulation records with AI analysis indicators
- **Strategic Insights**: AI-generated strategic assessment

### Persistent Analytics
- Simulation history automatically saved to database
- Analytics calculated from all user simulations
- ROI analysis tracked across all purchases
- Historical trends available on profile page

### AI Insights Panel
- Shows "Threat Narrative" section on dashboard
- Displays AI-generated analysis when available
- Recommends specific upgrades using AI
- Provides strategic insights based on historical data

---

## 🛠️ Configuration Options

### .env File Variables
```
# Flask
FLASK_ENV=development
FLASK_DEBUG=True

# Database
DATABASE_URL=sqlite:///cyber_killchain.db
SQLALCHEMY_ECHO=False

# AI (optional)
OPENAI_API_KEY=your_key_here

# App
SECRET_KEY=cyber_security_simulation_secret_2026
INITIAL_BUDGET=5000
```

---

## 📝 Usage Examples

### Register New User
```
1. Go to http://localhost:5000/register
2. Enter username, email, password
3. Account created with $5,000 initial budget
4. Automatically logged in
```

### Run Simulation (Logged In)
```
1. Select attack type
2. Click "Execute Attack"
3. Simulation saved to database
4. AI generates threat narrative and recommendations
5. Data added to your analytics dashboard
```

### View Profile Statistics
```
1. Click "View Profile" link in sidebar
2. See all-time statistics
3. Review recent simulations
4. Read AI-generated strategic insights
```

---

## 🔍 Database Queries Examples

### Get User's Simulations
```python
from app import db
from models import Simulation

user_sims = Simulation.query.filter_by(user_id=1).all()
```

### Get User Analytics
```python
from models import AnalyticsReport

report = AnalyticsReport.query.filter_by(user_id=1).first()
print(f"Average Score: {report.average_score}")
```

### Get All Upgrades Purchased
```python
from models import UpgradePurchase

upgrades = UpgradePurchase.query.filter_by(user_id=1).all()
```

---

## ⚠️ Important Notes

### AI Features
- OpenAI API calls cost money (currently ~$0.001 per request)
- Without API key, AI features gracefully degrade
- Recommendations still available from built-in rules
- Consider setting rate limits for production

### Database
- SQLite is suitable for development/testing
- For production, migrate to PostgreSQL or MySQL
- Backup `cyber_killchain.db` regularly
- Database grows with simulation history

### Security (Production)
- ⚠️ **DO NOT use plain text passwords in production**
- Implement proper password hashing (bcrypt, argon2)
- Add rate limiting for authentication
- Use HTTPS in production
- Implement proper session management

---

## 🚀 Next Steps

1. **Test User Registration**: Create a test account
2. **Run Simulations**: Generate simulation data
3. **Configure OpenAI**: Add API key for AI features
4. **View Profile**: Check analytics on profile page
5. **Export Data**: Use database tools to backup data

---

## 📚 Database Relationships

```
User (1) ──→ (Many) Simulations
      ├─────→ (Many) UpgradePurchases
      ├─────→ (Many) AnalyticsReports
      └─────→ (Many) AIInsights
```

---

## 🐛 Troubleshooting

### "OpenAI API key not configured"
- This is a warning, not an error
- Set OPENAI_API_KEY in .env file
- Restart the application

### Database locked error
- Close other connections to database
- Delete `cyber_killchain.db` to start fresh (loses data!)
- Restart the application

### Login always redirects to /login
- Clear browser cookies
- Check that user was created in registration
- Verify database file exists

---

## 📞 Support Information

For AI features: https://platform.openai.com/docs
For Flask-SQLAlchemy: https://flask-sqlalchemy.palletsprojects.com/
For issues: Check application logs in console

---

**Integration Status**: ✅ Complete
- Database: ✅ Implemented and working
- User Authentication: ✅ Implemented and working
- AI Advisor: ✅ Integrated (requires API key)
- Persistent Analytics: ✅ Working
