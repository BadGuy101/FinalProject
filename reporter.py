class ReportGenerator:
    """Generate comprehensive security reports"""
    
    def __init__(self):
        self.report_templates = {
            'summary': self._generate_summary_report,
            'detailed': self._generate_detailed_report,
            'threat_intelligence': self._generate_threat_intel_report,
            'performance': self._generate_performance_report
        }
    
    def generate_report(self, report_type, data, output_format='text'):
        """Generate specified type of report"""
        try:
            if report_type not in self.report_templates:
                return "Unknown report type"
            
            report_content = self.report_templates[report_type](data)
            
            if output_format == 'html':
                return self._format_as_html(report_content, report_type)
            elif output_format == 'json':
                return json.dumps(report_content, indent=2, default=str)
            else:
                return self._format_as_text(report_content)
                
        except Exception as e:
            logging.error(f"Error generating {report_type} report: {e}")
            return f"Error generating report: {e}"
    
    def _generate_summary_report(self, data):
        """Generate summary report"""
        return {
            'report_type': 'Security Summary',
            'timestamp': datetime.now().isoformat(),
            'scan_statistics': {
                'files_scanned': data.get('files_scanned', 0),
                'threats_detected': data.get('threats_detected', 0),
                'false_positives': data.get('false_positives', 0),
                'quarantined_files': data.get('quarantined_files', 0)
            },
            'system_health': {
                'cpu_usage': data.get('cpu_usage', 0),
                'memory_usage': data.get('memory_usage', 0),
                'disk_usage': data.get('disk_usage', 0)
            },
            'threat_categories': data.get('threat_categories', {}),
            'recommendations': self._generate_recommendations(data)
        }
    
    def _generate_detailed_report(self, data):
        """Generate detailed security report"""
        return {
            'report_type': 'Detailed Security Analysis',
            'timestamp': datetime.now().isoformat(),
            'executive_summary': self._create_executive_summary(data),
            'scan_details': data.get('scan_results', []),
            'threat_analysis': data.get('threat_analysis', {}),
            'system_analysis': data.get('system_analysis', {}),
            'network_analysis': data.get('network_analysis', {}),
            'ml_predictions': data.get('ml_predictions', {}),
            'quarantine_report': data.get('quarantine_stats', {}),
            'performance_metrics': data.get('performance_metrics', {}),
            'recommendations': self._generate_detailed_recommendations(data)
        }
    
    def _generate_threat_intel_report(self, data):
        """Generate threat intelligence report"""
        return {
            'report_type': 'Threat Intelligence',
            'timestamp': datetime.now().isoformat(),
            'intel_sources': data.get('intel_sources', {}),
            'threat_indicators': data.get('threat_indicators', {}),
            'emerging_threats': data.get('emerging_threats', []),
            'ioc_analysis': data.get('ioc_analysis', {}),
            'attribution': data.get('attribution', {}),
            'trend_analysis': data.get('trend_analysis', {})
        }
    
    def _generate_performance_report(self, data):
        """Generate performance analysis report"""
        return {
            'report_type': 'Performance Analysis',
            'timestamp': datetime.now().isoformat(),
            'ml_model_performance': data.get('model_performance', {}),
            'scan_performance': data.get('scan_performance', {}),
            'system_impact': data.get('system_impact', {}),
            'accuracy_metrics': data.get('accuracy_metrics', {}),
            'optimization_suggestions': self._generate_optimization_suggestions(data)
        }
    
    def _generate_recommendations(self, data):
        """Generate security recommendations"""
        recommendations = []
        
        # Based on threat count
        threat_count = data.get('threats_detected', 0)
        if threat_count > 10:
            recommendations.append("High threat activity detected. Consider running a full system scan.")
        elif threat_count > 5:
            recommendations.append("Moderate threat activity. Monitor system closely.")
        
        # Based on system performance
        cpu_avg = data.get('cpu_usage', 0)
        if cpu_avg > 80:
            recommendations.append("High CPU usage detected. Check for resource-intensive processes.")
        
        memory_avg = data.get('memory_usage', 0)
        if memory_avg > 90:
            recommendations.append("High memory usage. Consider closing unnecessary applications.")
        
        # Based on network activity
        suspicious_connections = data.get('suspicious_connections', 0)
        if suspicious_connections > 5:
            recommendations.append("Multiple suspicious network connections detected. Review network activity.")
        
        return recommendations
    
    def _generate_detailed_recommendations(self, data):
        """Generate detailed recommendations with priority levels"""
        recommendations = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        # Critical recommendations
        if data.get('threats_detected', 0) > 20:
            recommendations['critical'].append({
                'title': 'High Threat Volume',
                'description': 'Immediate action required due to high number of threats',
                'action': 'Run comprehensive system scan and update security definitions'
            })
        
        # High priority recommendations
        if data.get('quarantined_files', 0) > 0:
            recommendations['high'].append({
                'title': 'Quarantined Files Present',
                'description': 'Files have been quarantined and require attention',
                'action': 'Review quarantined files and determine if restoration is safe'
            })
        
        # Continue with medium and low priority...
        
        return recommendations
    
    def _create_executive_summary(self, data):
        """Create executive summary"""
        summary = []
        
        threats = data.get('threats_detected', 0)
        if threats == 0:
            summary.append("No threats detected during the scan period.")
        elif threats < 5:
            summary.append(f"Low threat activity: {threats} threats detected and contained.")
        else:
            summary.append(f"Elevated threat activity: {threats} threats detected.")
        
        quarantined = data.get('quarantined_files', 0)
        if quarantined > 0:
            summary.append(f"{quarantined} files have been quarantined for safety.")
        
        return ' '.join(summary)
    
    def _generate_optimization_suggestions(self, data):
        """Generate optimization suggestions"""
        suggestions = []
        
        model_performance = data.get('model_performance', {})
        for model_name, metrics in model_performance.items():
            accuracy = metrics.get('accuracy', 0)
            if accuracy < 0.8:
                suggestions.append(f"Consider retraining {model_name} model (accuracy: {accuracy:.2f})")
        
        scan_time = data.get('scan_performance', {}).get('average_scan_time', 0)
        if scan_time > 60:
            suggestions.append("Scan performance is slow. Consider optimizing file filtering.")
        
        return suggestions
    
    def _format_as_html(self, report_content, report_type):
        """Format report as HTML"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{report_type} Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; }}
                .section {{ margin: 20px 0; }}
                .metric {{ background-color: #e8f4fd; padding: 10px; margin: 5px 0; }}
                .threat {{ background-color: #ffe6e6; padding: 10px; margin: 5px 0; }}
                .recommendation {{ background-color: #e6ffe6; padding: 10px; margin: 5px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{report_content.get('report_type', 'Security Report')}</h1>
                <p>Generated: {report_content.get('timestamp', '')}</p>
            </div>
        """
        
        # Add sections based on report content
        for key, value in report_content.items():
            if key not in ['report_type', 'timestamp']:
                html += f'<div class="section"><h2>{key.replace("_", " ").title()}</h2>'
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        html += f'<div class="metric"><strong>{sub_key}:</strong> {sub_value}</div>'
                elif isinstance(value, list):
                    for item in value:
                        html += f'<div class="recommendation">• {item}</div>'
                else:
                    html += f'<p>{value}</p>'
                html += '</div>'
        
        html += "</body></html>"
        return html
    
    def _format_as_text(self, report_content):
        """Format report as plain text"""
        text = f"{report_content.get('report_type', 'Security Report')}\n"
        text += "=" * len(text) + "\n"
        text += f"Generated: {report_content.get('timestamp', '')}\n\n"
        
        for key, value in report_content.items():
            if key not in ['report_type', 'timestamp']:
                text += f"{key.replace('_', ' ').title()}:\n"
                text += "-" * (len(key) + 1) + "\n"
                
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        text += f"  {sub_key}: {sub_value}\n"
                elif isinstance(value, list):
                    for item in value:
                        text += f"  • {item}\n"
                else:
                    text += f"  {value}\n"
                text += "\n"
        
        return text