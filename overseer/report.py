"""
Report Generation Module
Handles the generation of analysis reports in various formats
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime


class ReportGenerator:
    """Generates analysis reports from collected data"""
    
    def __init__(self, analysis_dir: Path):
        self.analysis_dir = Path(analysis_dir)
        self.report_dir = self.analysis_dir / "reports"
        self.report_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(
        self,
        analysis_results: Dict[str, Any],
        report_format: str = "html"
    ) -> Path:
        """
        Generate a report from analysis results
        
        Args:
            analysis_results: Dictionary containing analysis data
            report_format: Format of report ('html', 'json', 'markdown')
        
        Returns:
            Path to the generated report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        binary_name = analysis_results.get("binary", {}).get("name", "unknown")
        
        if report_format == "html":
            return self._generate_html_report(analysis_results, timestamp, binary_name)
        elif report_format == "json":
            return self._generate_json_report(analysis_results, timestamp, binary_name)
        elif report_format == "markdown":
            return self._generate_markdown_report(analysis_results, timestamp, binary_name)
        else:
            raise ValueError(f"Unsupported report format: {report_format}")
    
    def _generate_html_report(
        self,
        results: Dict[str, Any],
        timestamp: str,
        binary_name: str
    ) -> Path:
        """Generate an HTML report"""
        report_path = self.report_dir / f"{binary_name}_{timestamp}.html"
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Malware Analysis Report - {binary_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #ddd; padding-bottom: 5px; }}
        .section {{ margin: 20px 0; }}
        .tool-result {{ background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .summary {{ background: #e8f4f8; padding: 15px; border-left: 4px solid #2196F3; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
    </style>
</head>
<body>
    <h1>Malware Analysis Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Binary:</strong> {binary_name}</p>
        <p><strong>Analysis Date:</strong> {timestamp}</p>
        <p><strong>Binary Path:</strong> {results.get('binary', {}).get('path', 'N/A')}</p>
    </div>
    
    <div class="section">
        <h2>Static Analysis Results</h2>
        {self._format_tool_results(results.get('static_results', {}))}
    </div>
    
    <div class="section">
        <h2>Dynamic Analysis Results</h2>
        {self._format_tool_results(results.get('dynamic_results', {}))}
    </div>
    
    <div class="section">
        <h2>Procmon Results</h2>
        {self._format_procmon_results(results.get('procmon_results', {}))}
    </div>
</body>
</html>
"""
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path
    
    def _generate_json_report(
        self,
        results: Dict[str, Any],
        timestamp: str,
        binary_name: str
    ) -> Path:
        """Generate a JSON report"""
        report_path = self.report_dir / f"{binary_name}_{timestamp}.json"
        
        report_data = {
            "binary": binary_name,
            "timestamp": timestamp,
            "analysis_results": results
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4)
        
        return report_path
    
    def _generate_markdown_report(
        self,
        results: Dict[str, Any],
        timestamp: str,
        binary_name: str
    ) -> Path:
        """Generate a Markdown report"""
        report_path = self.report_dir / f"{binary_name}_{timestamp}.md"
        
        md_content = f"""# Malware Analysis Report

## Summary
- **Binary:** {binary_name}
- **Analysis Date:** {timestamp}
- **Binary Path:** {results.get('binary', {}).get('path', 'N/A')}

## Static Analysis Results
{self._format_tool_results_markdown(results.get('static_results', {}))}

## Dynamic Analysis Results
{self._format_tool_results_markdown(results.get('dynamic_results', {}))}

## Procmon Results
{self._format_procmon_results_markdown(results.get('procmon_results', {}))}
"""
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        return report_path
    
    def _format_tool_results(self, tool_results: Dict[str, Any]) -> str:
        """Format tool results for HTML"""
        if not tool_results:
            return "<p>No results available</p>"
        
        html = ""
        for tool_name, result in tool_results.items():
            html += f"""
            <div class="tool-result">
                <h3>{tool_name}</h3>
                <pre>{json.dumps(result, indent=2)}</pre>
            </div>
            """
        return html
    
    def _format_tool_results_markdown(self, tool_results: Dict[str, Any]) -> str:
        """Format tool results for Markdown"""
        if not tool_results:
            return "No results available\n"
        
        md = ""
        for tool_name, result in tool_results.items():
            md += f"\n### {tool_name}\n\n```json\n{json.dumps(result, indent=2)}\n```\n"
        return md
    
    def _format_procmon_results(self, procmon_results: Dict[str, Any]) -> str:
        """Format Procmon results for HTML"""
        if not procmon_results:
            return "<p>No Procmon data available</p>"
        
        return f"""
        <div class="tool-result">
            <h3>Process Monitor</h3>
            <pre>{json.dumps(procmon_results, indent=2)}</pre>
        </div>
        """
    
    def _format_procmon_results_markdown(self, procmon_results: Dict[str, Any]) -> str:
        """Format Procmon results for Markdown"""
        if not procmon_results:
            return "No Procmon data available\n"
        
        return f"\n```json\n{json.dumps(procmon_results, indent=2)}\n```\n"


def generate_analysis_report(
    analysis_results: Dict[str, Any],
    output_dir: Path,
    report_format: str = "html"
) -> Path:
    """
    Convenience function to generate a report
    
    Args:
        analysis_results: Dictionary containing analysis data
        output_dir: Directory to save the report
        report_format: Format of report ('html', 'json', 'markdown')
    
    Returns:
        Path to the generated report file
    """
    generator = ReportGenerator(output_dir)
    return generator.generate_report(analysis_results, report_format)
