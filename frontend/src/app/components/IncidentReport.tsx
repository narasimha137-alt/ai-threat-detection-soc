import React from "react";

interface IncidentReportProps {
  report: string;
}

const IncidentReport: React.FC<IncidentReportProps> = ({ report }) => {
  return (
    <div className="bg-black/50 border border-cyan-500/30 rounded-lg p-4 text-green-400 font-mono text-sm whitespace-pre-wrap">
      {report || "No report available"}
    </div>
  );
};

export default IncidentReport;
