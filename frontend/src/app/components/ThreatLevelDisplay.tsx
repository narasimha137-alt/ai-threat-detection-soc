import React from "react";

type ThreatLevel = "LOW" | "MEDIUM" | "HIGH";

interface ThreatLevelDisplayProps {
  level: ThreatLevel;
  result?: any;
  confidenceThreshold?: number;
}

const ThreatLevelDisplay: React.FC<ThreatLevelDisplayProps> = ({
  level,
  result,
  confidenceThreshold = 50,
}) => {
  const getColor = () => {
    if (level === "HIGH") return "text-red-500";
    if (level === "MEDIUM") return "text-yellow-400";
    return "text-green-400";
  };

  return (
    <div className="text-center">
      <h2 className="text-xl font-mono text-gray-400 mb-2">
        Threat Level
      </h2>
      <div className={`text-5xl font-bold ${getColor()}`}>
        {level}
      </div>
      {result && (
        <p className="text-sm text-gray-500 mt-2">
          Confidence: {result.confidence ?? 0}%
        </p>
      )}
    </div>
  );
};

export default ThreatLevelDisplay;
