const API_BASE_URL =
  import.meta.env.VITE_API_URL || "http://localhost:8000";

export interface AnalysisResponse {
  email: any;
  domain_analysis: any;
  domain_intelligence: any;
  threat_analysis: any;
  url_analysis: any[];
  identity_correlation: any;
  ip_intelligence: any[];
  ip_locations: Record<string, any>;
  earliest_reliable_ip: any;
  relay_chain: any[];
  trace_comparison: any;
  attachment_analysis: any[];
  lookalike_analysis: any[];
  nlp_analysis: any;
  ml_phishing_analysis: any;
}

export async function analyzeEmail(
  file: File
): Promise<AnalysisResponse> {
  const formData = new FormData();

  formData.append("file", file);

  const response = await fetch(
    `${API_BASE_URL}/analyze`,
    {
      method: "POST",
      body: formData,
    }
  );

  if (!response.ok) {
    const message = await response.text();

    throw new Error(
      `Analysis failed (${response.status}): ${message}`
    );
  }

  return response.json();
}

export async function downloadForensicReport(
  file: File
): Promise<Blob> {
  const formData = new FormData();

  formData.append("file", file);

  const response = await fetch(
    `${API_BASE_URL}/analyze/report`,
    {
      method: "POST",
      body: formData,
    }
  );

  if (!response.ok) {
    throw new Error(
      `Report generation failed (${response.status})`
    );
  }

  return response.blob();
}