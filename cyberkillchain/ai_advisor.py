import os
from openai import OpenAI
import json
from typing import Optional, Dict, List

class AISecurityAdvisor:
    """AI-powered security advisor using OpenAI API"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        
        self.client = OpenAI(api_key=self.api_key)
        self.model = "gpt-3.5-turbo"
    
    def generate_threat_narrative(self, attack_type: str, detection_score: int, events: List[Dict]) -> str:
        """Generate a detailed threat narrative for a simulation"""
        
        detected_stages = [e['stage'] for e in events if e['status'] == 'Detected']
        missed_stages = [e['stage'] for e in events if e['status'] == 'Missed']
        
        prompt = f"""You are a cybersecurity threat analyst. Generate a concise threat narrative (3-4 sentences) 
for the following attack simulation:

Attack Type: {attack_type}
Detection Success Rate: {detection_score}%
Detected at Stages: {', '.join(detected_stages) if detected_stages else 'None'}
Missed at Stages: {', '.join(missed_stages) if missed_stages else 'None'}

Provide a realistic threat narrative that explains what happened during this attack. Be technical but understandable.
Keep it under 150 words."""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=200
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Error generating narrative: {str(e)}"
    
    def generate_intelligent_recommendations(self, attack_type: str, detection_score: int, 
                                             weakest_stages: List[str], current_upgrades: Dict) -> Dict:
        """Generate AI-powered remediation recommendations"""
        
        prompt = f"""You are a cybersecurity expert. Based on this attack simulation, provide intelligent 
remediation recommendations.

Attack Type: {attack_type}
Detection Success Rate: {detection_score}%
Weakest Stages: {', '.join(weakest_stages)}
Current Upgrades: {json.dumps(current_upgrades, indent=2)}

Provide 3-4 specific, actionable recommendations in JSON format:
{{
    "priority": "critical/high/medium",
    "immediate_actions": ["action1", "action2", ...],
    "upgrade_suggestions": ["upgrade1", "upgrade2", ...],
    "strategy": "Brief strategic recommendation"
}}

Focus on the weakest stages and suggest concrete improvements."""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=300
            )
            
            # Try to parse JSON response
            response_text = response.choices[0].message.content.strip()
            # Find JSON in response
            if '{' in response_text and '}' in response_text:
                json_start = response_text.find('{')
                json_end = response_text.rfind('}') + 1
                json_str = response_text[json_start:json_end]
                return json.loads(json_str)
            else:
                return {"priority": "medium", "immediate_actions": [], "upgrade_suggestions": [], "strategy": response_text}
        except Exception as e:
            return {
                "priority": "medium",
                "immediate_actions": ["Review security logs", "Check IDS alerts"],
                "upgrade_suggestions": [],
                "strategy": f"Error generating recommendations: {str(e)}"
            }

    def summarize_live_events(self, events: List[Dict]) -> str:
        """Summarize recent live events for the live dashboard."""
        prompt = f"""You are a SOC analyst. Summarize the recent live events in 3-5 bullet points.
Include: top attack types, most missed stages, and one recommended focus area.
Keep it concise and actionable.

Events (JSON):
{json.dumps(events, indent=2)}
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.4,
                max_tokens=200
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Error generating live brief: {str(e)}"

    def explain_recommendations(self, attack_type: str, event: Dict, recommendations: List[Dict]) -> str:
        """Explain why recommendations were generated for a live event."""
        prompt = f"""You are a cybersecurity analyst. Explain in 2-3 sentences why these recommendations fit the event.

Attack Type: {attack_type}
Event: {json.dumps(event, indent=2)}
Recommendations: {json.dumps(recommendations, indent=2)}
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.4,
                max_tokens=150
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Error explaining recommendations: {str(e)}"

    def suggest_next_steps(self, attack_type: str, event: Dict, playbook: Dict) -> List[str]:
        """Suggest next steps for a live event. Returns a list of steps."""
        prompt = f"""You are an incident response lead. Provide 3-5 immediate next steps in JSON.

Attack Type: {attack_type}
Event: {json.dumps(event, indent=2)}
Playbook (if any): {json.dumps(playbook, indent=2)}

Return only JSON in this format:
{{ "steps": ["step1", "step2", "step3"] }}
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=200
            )
            response_text = response.choices[0].message.content.strip()
            if '{' in response_text and '}' in response_text:
                json_start = response_text.find('{')
                json_end = response_text.rfind('}') + 1
                json_str = response_text[json_start:json_end]
                data = json.loads(json_str)
                steps = data.get("steps", [])
                return [s for s in steps if s][:5]
            return [s for s in response_text.split("\n") if s][:5]
        except Exception as e:
            return [f"Error generating next steps: {str(e)}"]

    def summarize_case(self, case: Dict, notes: List[Dict], simulation: Optional[Dict]) -> str:
        """Summarize a case with notes and linked simulation."""
        prompt = f"""You are a SOC analyst. Provide a concise case summary (4-6 sentences).
Include: what happened, current status, key evidence, and recommended next action.

Case: {json.dumps(case, indent=2)}
Notes: {json.dumps(notes, indent=2)}
Simulation: {json.dumps(simulation, indent=2)}
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.4,
                max_tokens=220
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Error generating case summary: {str(e)}"

    def analyze_root_cause(self, events: List[Dict]) -> str:
        """Analyze likely root cause from missed stages."""
        prompt = f"""You are a threat analyst. Determine the most likely root cause of missed detections.
Provide 3-4 bullet points that tie missed stages to likely controls gaps.

Events: {json.dumps(events, indent=2)}
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.4,
                max_tokens=200
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Error generating root cause: {str(e)}"

    def triage_score(self, case: Dict, simulation: Optional[Dict]) -> Dict:
        """Generate a triage score for a case."""
        prompt = f"""You are a SOC lead. Assign a triage score from 0-100 and a label.
Consider severity, status, and simulation detection score if present.
Return only JSON:
{{ "score": 0-100, "label": "Low/Medium/High/Critical", "rationale": "short" }}

Case: {json.dumps(case, indent=2)}
Simulation: {json.dumps(simulation, indent=2)}
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=150
            )
            response_text = response.choices[0].message.content.strip()
            if '{' in response_text and '}' in response_text:
                json_start = response_text.find('{')
                json_end = response_text.rfind('}') + 1
                json_str = response_text[json_start:json_end]
                data = json.loads(json_str)
                return {
                    "score": int(data.get("score", 0)),
                    "label": data.get("label", "Medium"),
                    "rationale": data.get("rationale", "")
                }
            return {"score": 50, "label": "Medium", "rationale": response_text}
        except Exception as e:
            return {"score": 50, "label": "Medium", "rationale": f"Error: {str(e)}"}
    
    def analyze_defense_strategy(self, total_simulations: int, average_score: float, 
                                 attack_breakdown: Dict, total_invested: int) -> str:
        """Analyze overall defense strategy and provide insights"""
        
        prompt = f"""You are a chief information security officer analyzing defense metrics.

Total Simulations: {total_simulations}
Average Detection Score: {average_score:.1f}%
Attack Effectiveness (Attack Type: Avg Score):
{json.dumps(attack_breakdown, indent=2)}
Total Budget Spent: ${total_invested:,}

Provide a strategic assessment (3-4 sentences) of the current defense posture:
1. What areas are well-defended?
2. What are the critical gaps?
3. What should be the next priority?

Be specific and actionable."""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=250
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Error analyzing strategy: {str(e)}"
    
    def get_attack_insights(self, attack_type: str, successful_rate: float) -> str:
        """Get insights about a specific attack type"""
        
        prompt = f"""You are a threat intelligence analyst. Provide a brief tactical brief (2-3 sentences) 
about {attack_type} attacks:

Success Rate in Tests: {successful_rate:.1f}%

Include:
1. How attackers typically execute this attack
2. Why it's effective against certain defenses
3. Key countermeasures

Be concise and educational."""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=200
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Error getting insights: {str(e)}"
    
    def suggest_optimal_upgrades(self, budget: int, current_upgrades: Dict, 
                                 weak_stages: List[str], historical_scores: List[int]) -> Dict:
        """Use AI to suggest optimal upgrade purchases"""
        
        avg_score = sum(historical_scores) / len(historical_scores) if historical_scores else 0
        
        prompt = f"""You are a cybersecurity budget optimizer. Recommend upgrade purchases.

Available Budget: ${budget:,}
Current Upgrades: {json.dumps(current_upgrades)}
Weakest Stages: {', '.join(weak_stages)}
Average Detection Score: {avg_score:.1f}%

Suggest up to 3 priority upgrades in JSON format:
{{
    "recommendations": [
        {{"upgrade": "name", "reason": "why", "expected_improvement": "%"}},
        ...
    ],
    "budget_allocation": "how to split the budget",
    "expected_outcome": "predicted improvement"
}}"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=300
            )
            
            response_text = response.choices[0].message.content.strip()
            if '{' in response_text and '}' in response_text:
                json_start = response_text.find('{')
                json_end = response_text.rfind('}') + 1
                json_str = response_text[json_start:json_end]
                return json.loads(json_str)
            else:
                return {"recommendations": [], "budget_allocation": response_text, "expected_outcome": ""}
        except Exception as e:
            return {
                "recommendations": [],
                "budget_allocation": "Contact system administrator",
                "expected_outcome": f"Error: {str(e)}"
            }

    def compute_metrics(self, history: List[Dict]) -> Dict:
        """Compute aggregate metrics from simulation history using the AI model.
        Expects history as a list of objects with keys: 'attack' and 'score'.
        Returns a dict with: avg_score, max_score, min_score, total_simulations, attack_breakdown, scores
        """
        try:
            # Make a concise, machine-parseable prompt asking for JSON only
            prompt = f"""You are a data analyst. Given the following JSON array of simulation results, compute exact
aggregate metrics and return ONLY a JSON object. The input is an array of objects like:
[{{"attack": "Phishing", "score": 70}}, {{"attack": "Malware", "score": 80}}, ...]

Return a JSON object with the following keys:
{
  "avg_score": <integer>,
  "max_score": <integer>,
  "min_score": <integer>,
  "total_simulations": <integer>,
  "attack_breakdown": {{"Phishing": 72, "Malware": 80}},
  "scores": [list of last up to 10 scores in most recent-first order]
}

Here is the data:
{json.dumps(history)}

Only output the JSON object and nothing else."""

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=400
            )

            response_text = response.choices[0].message.content.strip()
            # Extract JSON substring
            if '{' in response_text and '}' in response_text:
                json_start = response_text.find('{')
                json_end = response_text.rfind('}') + 1
                json_str = response_text[json_start:json_end]
                data = json.loads(json_str)
                # Normalize types
                data['avg_score'] = int(data.get('avg_score', 0))
                data['max_score'] = int(data.get('max_score', 0))
                data['min_score'] = int(data.get('min_score', 0))
                data['total_simulations'] = int(data.get('total_simulations', 0))
                data['attack_breakdown'] = {k: int(v) for k, v in data.get('attack_breakdown', {}).items()}
                data['scores'] = list(data.get('scores', []))[:10]
                return data
            else:
                return None
        except Exception as e:
            # On any error, return None to indicate failure and let the caller fallback
            print(f"AI compute_metrics error: {e}")
            return None

    def generate_threat_summary(self, discoveries: List[Dict]) -> str:
        """Summarize newly discovered threats from logs/simulations."""
        prompt = f"""You are a threat intelligence analyst. Summarize the following newly discovered threat patterns.
Provide 3-5 bullet points, each describing a pattern, potential impact, and suggested next steps.

Data (JSON):
{json.dumps(discoveries, indent=2)}

Be concise and actionable."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.4,
                max_tokens=300
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"Error generating threat summary: {str(e)}"
