# Quick Start: Database & AI Integration

## ✨ What's New?

### Database Features
- ✅ User accounts with email/password
- ✅ Persistent simulation history
- ✅ Analytics dashboard with charts
- ✅ Upgrade purchase tracking
- ✅ ROI analysis per upgrade

### AI Features
- 🤖 AI-generated threat narratives
- 🤖 Intelligent upgrade recommendations
- 🤖 Strategic defense analysis
- 🤖 Attack vector insights
- 🤖 Budget optimization suggestions

---

## 🚀 Getting Started (30 seconds)

### Step 1: Set OpenAI API Key (Optional but Recommended)
```
1. Get free $5 credit: https://platform.openai.com/account/billing/overview
2. Create API key: https://platform.openai.com/api-keys
3. Edit .env file in project folder
4. Find this line: OPENAI_API_KEY=
5. Add your key: OPENAI_API_KEY=sk-your-key-here
6. Save and restart app
```

### Step 2: Create Account
```
1. Open http://localhost:5000
2. Click "Register here"
3. Enter: username, email, password
4. Start playing!
```

### Step 3: Run Simulations
```
1. Select attack type (Phishing, Malware, etc.)
2. Click "Execute Attack"
3. View results with AI analysis
4. Check profile for full statistics
```

---

## 📊 Key New Pages

### `/register` - Create Account
- New user registration
- Email and password storage
- Automatic login after signup

### `/login` - Sign In
- Login with username/password
- Session-based authentication
- Remember last login time

### `/user/profile` - Your Dashboard
- Performance stats (avg score, max score, etc.)
- Attack type effectiveness chart
- Recent simulation history
- AI-generated strategic insights
- Strongest/weakest defense areas

### `/` - Main Dashboard (Updated)
- Shows logged-in username
- All features work with database
- Simulations saved automatically
- Analytics from database queries

---

## 💡 AI Features Explained

### Threat Narrative
**What**: AI-generated story of what happened in your simulation
**Example**: "The attacker successfully bypassed your email filters with a sophisticated phishing campaign targeting finance department staff..."
**When**: After each simulation (if API key configured)

### Intelligent Recommendations
**What**: AI suggests which upgrades to buy based on weaknesses
**Example**: "Priority: Critical - Your Delivery stage is vulnerable. Recommended: Security Awareness Training ($800)"
**When**: Shown after simulation with missed detections

### Strategic Insights  
**What**: AI analyzes your overall defense strategy
**Example**: "Your defenses are strongest against DDoS (85%) but weakest against APT (45%). Focus on threat intelligence integration."
**When**: Displayed on profile after 3+ simulations

---

## 🔒 Accounts vs Guest Mode

### With Account (Recommended)
✅ Persistent data across sessions
✅ Full analytics and history
✅ Profile statistics
✅ Upgrade tracking
✅ AI insights

### Guest Mode (Session Only)
✓ Play immediately without signup
✗ Data lost when browser closes
✗ No analytics history
✗ No upgrade tracking

---

## 📈 Example: Using AI for Strategy

1. **Run 5 simulations** with different attack types
2. **Check profile** at `/user/profile`
3. **Read AI insights**: "You defend well against Phishing (82%) but struggle with APT (38%)"
4. **Ask AI for upgrades**: System suggests buying threat intel tools
5. **Purchase upgrades** recommended by AI
6. **Run more simulations** to test new defenses
7. **Check improvements** in analytics

---

## 🎯 New Database Models at a Glance

| Model | Purpose | Key Fields |
|-------|---------|-----------|
| **User** | Account info | username, email, budget |
| **Simulation** | Attack run data | attack_type, score, events |
| **UpgradePurchase** | Tracked purchases | upgrade_name, cost, date |
| **AnalyticsReport** | Aggregated stats | avg_score, attack_breakdown |
| **AIInsight** | Stored AI analysis | insight_type, content |

---

## 🛠️ Configuration Files

### .env (Recommended to Edit)
```
OPENAI_API_KEY=sk-your-api-key  ← Add your key here!
DATABASE_URL=sqlite:///cyber_killchain.db
INITIAL_BUDGET=5000
```

### cyber_killchain.db (Auto-Created)
- SQLite database file
- Stores all user data
- Created automatically on first run
- No setup needed

---

## 📱 Mobile-Friendly Features

- Responsive design for all screens
- Touch-friendly buttons
- Auto-scaling layout
- Works on phone, tablet, desktop

---

## 🔐 Security Notes

✅ Passwords stored in database (upgrade to bcrypt in production)
✅ Sessions secure with secret key
✅ HTTPS ready (configure in production)
✅ Input validation on forms
⚠️ Don't commit .env file with real API keys to git

---

## 💰 API Cost Estimate

- OpenAI API: ~$0.001 per simulation
- $1 budget = ~1000 simulations with AI analysis
- Free tier: $5 monthly credit from OpenAI

---

## 🆘 Quick Troubleshooting

**App won't start?**
```
python -m py_compile app.py
```
Check for syntax errors

**Database issues?**
```
Delete cyber_killchain.db
Restart app (rebuilds database)
```

**API not working?**
```
Check OPENAI_API_KEY in .env
Restart app after saving
Check it's not empty or incomplete
```

**Forgot password?**
```
Delete cyber_killchain.db
Register new account (loses all data!)
Or use database tool to update password_hash
```

---

## 🎮 Sample Workflow

```
1. Register: username "SecurityChief", email "sec@company.com"
2. See: $5000 budget, empty history
3. Select: "Phishing" attack
4. See: 65% detection score, AI threat narrative
5. View: "Delivery stage missed - user clicked link"
6. AI suggests: Buy "Security Awareness Training"
7. Check profile: 1 simulation recorded
8. Purchase upgrade: -$800, +18% boost
9. Run phishing again: Now 78% detection!
10. Profile shows: History, trend, improvements
```

---

**You're all set! Open http://localhost:5000 and start playing! 🚀**
