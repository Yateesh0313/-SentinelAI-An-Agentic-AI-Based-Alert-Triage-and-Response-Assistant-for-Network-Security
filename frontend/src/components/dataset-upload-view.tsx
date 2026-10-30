"use client";

import React, { useState, useRef } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

const API_BASE = "http://localhost:8000";

interface UploadAlertSummary {
  event_id: string | null;
  row_index: number;
  source_ip?: string | null;
  destination_ip?: string | null;
  source_port?: number | string | null;
  destination_port?: number | string | null;
  attack_category?: string | null;
  prediction: string;
  confidence: number;
  severity?: string | null;
  risk_score?: number | null;
  risk_classification?: string | null;
  recommended_action?: string | null;
  triage_summary?: string | null;
}

interface UploadSuccessResponse {
  status: "success";
  filename: string;
  schema: string;
  format_display: string;
  model_used: string;
  total_rows: number;
  processed_rows: number;
  anomalies_detected: number;
  normal_traffic: number;
  triaged_alerts: number;
  columns_matched: string[];
  columns_defaulted: string[];
  alerts: UploadAlertSummary[];
}

interface TemplateEvaluation {
  matched_count: number;
  total_expected: number;
  missing_key_columns: string[];
}

interface UploadErrorResponse {
  error?: string;
  error_type?: string;
  status_code?: number;
  title?: string;
  message?: string;
  detail?: string;
  uploaded_column_count?: number;
  uploaded_columns_sample?: string[];
  templates_evaluated?: {
    "NSL-KDD"?: TemplateEvaluation;
    "CICIDS2017"?: TemplateEvaluation;
    "UNSW-NB15"?: TemplateEvaluation;
  };
  hint?: string;
}

export function DatasetUploadView({
  onViewLiveFeed,
}: {
  onViewLiveFeed?: () => void;
}) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [modelType, setModelType] = useState<"xgboost" | "random_forest">("xgboost");
  const [maxRows, setMaxRows] = useState<number>(100);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [loadingSample, setLoadingSample] = useState<string | null>(null);

  const [result, setResult] = useState<UploadSuccessResponse | null>(null);
  const [errorResult, setErrorResult] = useState<UploadErrorResponse | null>(null);
  const [showMappingDetails, setShowMappingDetails] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // File selection
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
      setResult(null);
      setErrorResult(null);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith(".csv")) {
        setSelectedFile(file);
        setResult(null);
        setErrorResult(null);
      } else {
        alert("Please drop a valid .csv file.");
      }
    }
  };

  // Upload handler
  const handleUpload = async (fileToUpload?: File) => {
    const file = fileToUpload || selectedFile;
    if (!file) return;

    setLoading(true);
    setResult(null);
    setErrorResult(null);

    const formData = new FormData();
    formData.append("file", file);
    formData.append("model_type", modelType);
    formData.append("max_rows", maxRows.toString());

    // Extract JWT token from client storage
    const token = typeof window !== "undefined" ? localStorage.getItem("sentinel_token") : null;
    const headers: Record<string, string> = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    // CRITICAL REQUIREMENT A: Do NOT set Content-Type header manually for FormData!
    // The browser automatically sets Content-Type: multipart/form-data; boundary=...

    try {
      const res = await fetch(`${API_BASE}/dataset/upload`, {
        method: "POST",
        headers,
        body: formData,
      });

      if (!res.ok) {
        let errData: any = {};
        try {
          errData = await res.json();
        } catch {
          errData = { detail: res.statusText || "Request failed" };
        }

        // Distinct error messages for 401, 403, 413, and schema mismatch (400)
        if (res.status === 401) {
          setErrorResult({
            status_code: 401,
            error_type: "auth_required",
            title: "Authentication Required (401 Unauthorized)",
            message: "Not authenticated. Please log in with an Analyst or Admin account to upload datasets.",
            detail: errData.detail || "Authentication token was missing, invalid, or expired.",
          });
        } else if (res.status === 403) {
          setErrorResult({
            status_code: 403,
            error_type: "forbidden",
            title: "Access Forbidden (403 Insufficient Privileges)",
            message: "Your current account role does not have permission to upload datasets. Minimum required role: Analyst.",
            detail: errData.detail || "Insufficient permissions.",
          });
        } else if (res.status === 413) {
          setErrorResult({
            status_code: 413,
            error_type: "file_too_large",
            title: "File Too Large (413 Payload Too Large)",
            message: errData.detail || "The uploaded CSV file exceeds the 50 MB maximum size limit.",
            detail: errData.detail,
          });
        } else if (res.status === 400 && errData.error === "schema_detection_failed") {
          setErrorResult({
            status_code: 400,
            error_type: "schema_mismatch",
            title: "Schema Detection Error: Unrecognized Format",
            message: errData.message || "Uploaded CSV does not match any recognized NIDS template.",
            ...errData,
          });
        } else {
          setErrorResult({
            status_code: res.status,
            error_type: "validation_error",
            title: `Upload Error (${res.status})`,
            message: errData.detail || errData.message || "Failed to process the uploaded dataset.",
            ...errData,
          });
        }
      } else {
        const data = await res.json();
        setResult(data);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Network error";
      setErrorResult({
        error: "network_error",
        error_type: "network_error",
        title: "Network Connection Error",
        detail: `Failed to connect to backend server: ${msg}`,
      });
    } finally {
      setLoading(false);
      setLoadingSample(null);
    }
  };

  // 1-Click sample benchmark test
  const handleTestSample = async (templateName: string) => {
    setLoadingSample(templateName);
    setResult(null);
    setErrorResult(null);
    try {
      const res = await fetch(`${API_BASE}/dataset/sample/${templateName}`);
      if (!res.ok) throw new Error("Failed to fetch sample dataset");
      const blob = await res.blob();
      const filename = `${templateName}_sample.csv`;
      const file = new File([blob], filename, { type: "text/csv" });
      setSelectedFile(file);
      await handleUpload(file);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load sample";
      setErrorResult({
        error: "sample_load_failed",
        title: "Sample Load Failed",
        detail: msg,
      });
      setLoading(false);
      setLoadingSample(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Info Card */}
      <Card className="border-indigo-200 bg-gradient-to-r from-indigo-50/50 via-white to-indigo-50/30">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[0.65rem] font-bold uppercase tracking-widest bg-indigo-100 text-indigo-700 border border-indigo-200">
                NIDS Benchmark Pipeline
              </span>
              <CardTitle className="text-lg font-bold text-slate-900">
                Dataset Ingestion &amp; Schema Mapping
              </CardTitle>
            </div>
            {onViewLiveFeed && (
              <Button
                size="sm"
                variant="outline"
                onClick={onViewLiveFeed}
                className="text-xs bg-white text-indigo-700 border-indigo-200 hover:bg-indigo-50"
              >
                Live Feed Stream &rarr;
              </Button>
            )}
          </div>
          <CardDescription className="text-slate-600 text-xs mt-1 leading-relaxed">
            Upload raw CSV files from standard Network Intrusion Detection benchmarks (<strong>NSL-KDD</strong>,{" "}
            <strong>CICIDS2017</strong>, or <strong>UNSW-NB15</strong>). SentinelAI automatically verifies the schema
            without guessing, maps all attributes to the model&apos;s feature space, and streams flagged alerts
            directly into the live agent triage pipeline.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* 1-Click Quick Samples */}
          <div className="pt-2 border-t border-indigo-100 flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-slate-600 mr-1">⚡ 1-Click Test Samples:</span>
            <Button
              size="xs"
              variant="outline"
              onClick={() => handleTestSample("nsl")}
              disabled={loading}
              className="bg-white hover:bg-indigo-50 text-indigo-700 border-indigo-200 font-medium text-xs"
            >
              {loadingSample === "nsl" ? "Testing…" : "NSL-KDD (41 Features)"}
            </Button>
            <Button
              size="xs"
              variant="outline"
              onClick={() => handleTestSample("cic")}
              disabled={loading}
              className="bg-white hover:bg-cyan-50 text-cyan-800 border-cyan-200 font-medium text-xs"
            >
              {loadingSample === "cic" ? "Testing…" : "CICIDS2017 (FlowMeter)"}
            </Button>
            <Button
              size="xs"
              variant="outline"
              onClick={() => handleTestSample("unsw_full")}
              disabled={loading}
              className="bg-white hover:bg-purple-50 text-purple-800 border-purple-200 font-medium text-xs"
              title="UNSW-NB15 raw full-file layout with srcip, dstip, sport, dsport (49 columns)"
            >
              {loadingSample === "unsw_full" ? "Testing…" : "UNSW-NB15 (Full File 49-Col)"}
            </Button>
            <Button
              size="xs"
              variant="outline"
              onClick={() => handleTestSample("unsw")}
              disabled={loading}
              className="bg-white hover:bg-emerald-50 text-emerald-800 border-emerald-200 font-medium text-xs"
              title="UNSW-NB15 standardized training/testing set (45 columns)"
            >
              {loadingSample === "unsw" ? "Testing…" : "UNSW-NB15 (Training Set 45-Col)"}
            </Button>
            <Button
              size="xs"
              variant="outline"
              onClick={() => handleTestSample("invalid")}
              disabled={loading}
              className="bg-white hover:bg-red-50 text-red-700 border-red-200 font-medium text-xs"
              title="Test rejection of non-matching CSV"
            >
              {loadingSample === "invalid" ? "Testing…" : "❌ Test Invalid Schema"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Upload Zone & Configuration */}
      <Card className="border-slate-200 bg-white">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-bold text-slate-900">Upload Dataset CSV</CardTitle>
          <CardDescription className="text-xs text-slate-500">
            Select or drag-and-drop a network intrusion detection CSV file.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Controls: Model & Row limit */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 p-3 bg-slate-50 rounded-lg border border-slate-200">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Detection Classifier
              </label>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setModelType("xgboost")}
                  className={`flex-1 py-1.5 px-3 rounded text-xs font-semibold border transition-all ${
                    modelType === "xgboost"
                      ? "bg-blue-600 text-white border-blue-600 shadow-sm"
                      : "bg-white text-slate-700 border-slate-300 hover:bg-slate-100"
                  }`}
                >
                  XGBoost (Production)
                </button>
                <button
                  type="button"
                  onClick={() => setModelType("random_forest")}
                  className={`flex-1 py-1.5 px-3 rounded text-xs font-semibold border transition-all ${
                    modelType === "random_forest"
                      ? "bg-blue-600 text-white border-blue-600 shadow-sm"
                      : "bg-white text-slate-700 border-slate-300 hover:bg-slate-100"
                  }`}
                >
                  Random Forest
                </button>
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Max Rows to Process
              </label>
              <select
                value={maxRows}
                onChange={(e) => setMaxRows(Number(e.target.value))}
                className="w-full text-xs bg-white border border-slate-300 rounded px-2.5 py-1.5 text-slate-800 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value={50}>50 rows (Fast)</option>
                <option value={100}>100 rows (Standard)</option>
                <option value={250}>250 rows (Deep Batch)</option>
                <option value={500}>500 rows (Comprehensive)</option>
              </select>
            </div>
          </div>

          {/* Drag & Drop Area */}
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
              isDragging
                ? "border-blue-500 bg-blue-50/50 scale-[0.99]"
                : selectedFile
                ? "border-indigo-300 bg-indigo-50/20"
                : "border-slate-300 hover:border-blue-400 bg-slate-50/50 hover:bg-slate-50"
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv"
              onChange={handleFileChange}
              className="hidden"
            />

            <div className="flex flex-col items-center justify-center gap-2">
              <div className="w-12 h-12 rounded-full bg-indigo-50 flex items-center justify-center text-indigo-600 border border-indigo-100">
                <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
              </div>

              {selectedFile ? (
                <div>
                  <p className="text-sm font-bold text-slate-900">{selectedFile.name}</p>
                  <p className="text-xs text-slate-500 mt-0.5">
                    {(selectedFile.size / 1024).toFixed(1)} KB &bull; Click or drop another file to replace
                  </p>
                </div>
              ) : (
                <div>
                  <p className="text-sm font-semibold text-slate-700">
                    Click to browse or drag and drop your dataset CSV here
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    Accepts NSL-KDD, CICIDS2017, and UNSW-NB15 format files
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Action button */}
          <div className="flex items-center justify-end gap-3 pt-2">
            {selectedFile && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setSelectedFile(null);
                  setResult(null);
                  setErrorResult(null);
                }}
                disabled={loading}
                className="text-xs text-slate-500 hover:text-slate-700"
              >
                Clear
              </Button>
            )}

            <Button
              size="sm"
              onClick={() => handleUpload()}
              disabled={!selectedFile || loading}
              className="bg-blue-600 hover:bg-blue-700 text-white gap-2 text-xs font-semibold px-5 shadow-sm"
            >
              {loading ? (
                <>
                  <svg className="animate-spin w-3.5 h-3.5" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  <span>Processing Dataset &amp; Triage…</span>
                </>
              ) : (
                <>
                  <span>🚀</span>
                  <span>Detect Schema &amp; Analyze</span>
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* ERROR FEEDBACK BANNER (Requirement A: Distinct messages for 401, 403, 413, and schema mismatch) */}
      {errorResult && (
        <Card className="border-red-200 bg-red-50/40">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-6 h-6 rounded-full bg-red-100 flex items-center justify-center text-red-600 text-xs font-bold">
                  ✕
                </span>
                <CardTitle className="text-sm font-bold text-red-800">
                  {errorResult.title || "Dataset Processing Error"}
                </CardTitle>
              </div>
              {errorResult.status_code === 401 && (
                <Button
                  size="xs"
                  onClick={() => window.location.href = "/login"}
                  className="bg-red-600 hover:bg-red-700 text-white text-xs font-semibold"
                >
                  Go to Login &rarr;
                </Button>
              )}
            </div>
            <CardDescription className="text-xs text-red-700 mt-1">
              {errorResult.message || errorResult.detail || "An error occurred during dataset processing."}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 pt-1">
            {errorResult.error_type === "auth_required" && (
              <div className="p-3 bg-white rounded border border-red-200 text-xs text-slate-700 space-y-1.5">
                <p className="font-semibold text-red-800">Role-Based Access Control (RBAC):</p>
                <p>Dataset ingestion requires Analyst or Admin credentials. If your session has expired, please log back in to SentinelAI to proceed.</p>
              </div>
            )}

            {errorResult.error_type === "forbidden" && (
              <div className="p-3 bg-white rounded border border-red-200 text-xs text-slate-700 space-y-1.5">
                <p className="font-semibold text-red-800">Insufficient Privileges:</p>
                <p>Viewer accounts cannot upload datasets or trigger automated triage runs. Please switch to an Analyst or Admin account.</p>
              </div>
            )}

            {errorResult.error_type === "file_too_large" && (
              <div className="p-3 bg-white rounded border border-red-200 text-xs text-slate-700 space-y-1.5">
                <p className="font-semibold text-red-800">File Exceeds Size Limit:</p>
                <p>The maximum upload file size is <strong>50 MB</strong>. For larger benchmark datasets, please split the file or use the Max Ingestion Rows selector.</p>
              </div>
            )}

            {errorResult.templates_evaluated && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                {/* NSL-KDD Check */}
                <div className="p-2.5 rounded bg-white border border-red-200 space-y-1">
                  <div className="font-bold text-slate-800 flex justify-between">
                    <span>NSL-KDD</span>
                    <span className="text-red-600 font-mono">
                      {errorResult.templates_evaluated["NSL-KDD"]?.matched_count ?? 0} /{" "}
                      {errorResult.templates_evaluated["NSL-KDD"]?.total_expected ?? 41}
                    </span>
                  </div>
                  <div className="text-[0.65rem] text-slate-500">
                    Missing columns:{" "}
                    <span className="text-slate-700 font-mono">
                      {errorResult.templates_evaluated["NSL-KDD"]?.missing_key_columns?.slice(0, 4).join(", ") || "none"}…
                    </span>
                  </div>
                </div>

                {/* CICIDS2017 Check */}
                <div className="p-2.5 rounded bg-white border border-red-200 space-y-1">
                  <div className="font-bold text-slate-800 flex justify-between">
                    <span>CICIDS2017</span>
                    <span className="text-red-600 font-mono">
                      {errorResult.templates_evaluated["CICIDS2017"]?.matched_count ?? 0} /{" "}
                      {errorResult.templates_evaluated["CICIDS2017"]?.total_expected ?? 79}
                    </span>
                  </div>
                  <div className="text-[0.65rem] text-slate-500">
                    Missing columns:{" "}
                    <span className="text-slate-700 font-mono">
                      {errorResult.templates_evaluated["CICIDS2017"]?.missing_key_columns?.slice(0, 4).join(", ") || "none"}…
                    </span>
                  </div>
                </div>

                {/* UNSW-NB15 Check */}
                <div className="p-2.5 rounded bg-white border border-red-200 space-y-1">
                  <div className="font-bold text-slate-800 flex justify-between">
                    <span>UNSW-NB15</span>
                    <span className="text-red-600 font-mono">
                      {errorResult.templates_evaluated["UNSW-NB15"]?.matched_count ?? 0} /{" "}
                      {errorResult.templates_evaluated["UNSW-NB15"]?.total_expected ?? 45}
                    </span>
                  </div>
                  <div className="text-[0.65rem] text-slate-500">
                    Missing columns:{" "}
                    <span className="text-slate-700 font-mono">
                      {errorResult.templates_evaluated["UNSW-NB15"]?.missing_key_columns?.slice(0, 4).join(", ") || "none"}…
                    </span>
                  </div>
                </div>
              </div>
            )}

            {errorResult.uploaded_columns_sample && (
              <div className="p-2.5 rounded bg-white border border-red-200 text-xs">
                <span className="font-semibold text-slate-700">Uploaded Columns Sample: </span>
                <span className="font-mono text-[0.7rem] text-slate-600">
                  {errorResult.uploaded_columns_sample.join(", ")}
                </span>
              </div>
            )}

            <p className="text-[0.7rem] text-slate-500 italic">
              {errorResult.hint || "Please make sure your CSV contains standard headers for NSL-KDD, CICIDS2017, or UNSW-NB15."}
            </p>
          </CardContent>
        </Card>
      )}

      {/* Loading Skeleton State */}
      {loading && (
        <Card className="border-slate-200 bg-white">
          <CardContent className="p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="skeleton h-8 w-8 rounded-full" />
              <div className="space-y-1.5 flex-1">
                <div className="skeleton h-4 w-48" />
                <div className="skeleton h-3 w-72" />
              </div>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
              <div className="skeleton h-16 rounded-lg" />
              <div className="skeleton h-16 rounded-lg" />
              <div className="skeleton h-16 rounded-lg" />
              <div className="skeleton h-16 rounded-lg" />
            </div>
            <div className="skeleton h-24 rounded-lg" />
          </CardContent>
        </Card>
      )}

      {/* Empty State */}
      {!result && !errorResult && !loading && (
        <div className="text-center py-10 px-4 rounded-xl border border-dashed border-slate-200 bg-white/60">
          <div className="text-3xl mb-2">📊</div>
          <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider">Awaiting Dataset</h4>
          <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
            Select a CSV file above or test an automated sample to view schema detection, triage analysis, and detected threat categories.
          </p>
        </div>
      )}

      {/* SUCCESS RESULTS & DETECTED FORMAT BANNER (Requirement 6) */}
      {result && (
        <div className="space-y-6">
          {/* Detected Format Banner */}
          <Card className="border-emerald-300 bg-emerald-50/40 shadow-sm">
            <CardContent className="p-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-full bg-emerald-100 border border-emerald-300 flex items-center justify-center text-emerald-700 font-bold text-base">
                    ✓
                  </div>
                  <div>
                    {/* Exact format display as required by prompt */}
                    <div className="text-sm sm:text-base font-bold text-slate-900 tracking-tight" id="detected-schema-format">
                      {result.format_display}
                    </div>
                    <div className="text-xs text-slate-600 mt-0.5 flex items-center gap-2 flex-wrap">
                      <span>File: <strong className="text-slate-800">{result.filename}</strong></span>
                      <span>&bull;</span>
                      <span>Model: <strong className="text-slate-800">{result.model_used}</strong></span>
                      <span>&bull;</span>
                      <span>Mapped: <strong className="text-emerald-700">{result.columns_matched.length} features</strong></span>
                      {result.columns_defaulted.length > 0 && (
                        <span>({result.columns_defaulted.length} safe defaults)</span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    size="xs"
                    variant="outline"
                    onClick={() => setShowMappingDetails(!showMappingDetails)}
                    className="text-xs bg-white border-slate-300 text-slate-700 hover:bg-slate-50"
                  >
                    {showMappingDetails ? "Hide Mapping Details" : "View Mapping Details"}
                  </Button>
                  {onViewLiveFeed && (
                    <Button
                      size="xs"
                      onClick={onViewLiveFeed}
                      className="text-xs bg-indigo-600 hover:bg-indigo-700 text-white font-semibold"
                    >
                      View in Live Feed &rarr;
                    </Button>
                  )}
                </div>
              </div>

              {/* Collapsible Mapping Details */}
              {showMappingDetails && (
                <div className="mt-4 pt-3 border-t border-emerald-200 text-xs space-y-3">
                  <div>
                    <span className="font-semibold text-slate-700">Directly Mapped Columns ({result.columns_matched.length}):</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {result.columns_matched.map((col) => (
                        <span key={col} className="px-1.5 py-0.5 rounded text-[0.65rem] font-mono bg-white border border-emerald-200 text-emerald-800">
                          ✓ {col}
                        </span>
                      ))}
                    </div>
                  </div>

                  {result.columns_defaulted.length > 0 && (
                    <div>
                      <span className="font-semibold text-slate-700">Safe Defaulted Columns ({result.columns_defaulted.length}):</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {result.columns_defaulted.map((col) => (
                          <span key={col} className="px-1.5 py-0.5 rounded text-[0.65rem] font-mono bg-slate-100 border border-slate-200 text-slate-600" title="Defaulted to 0.0 or standard nominal value">
                            • {col}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Metrics Overview Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <Card className="border-slate-200 bg-white">
              <CardContent className="p-4">
                <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Processed Rows</div>
                <div className="text-2xl font-black text-slate-900 mt-1">{result.processed_rows}</div>
                <div className="text-[0.65rem] text-slate-400 mt-0.5">Total ingested</div>
              </CardContent>
            </Card>

            <Card className="border-emerald-200 bg-emerald-50/20">
              <CardContent className="p-4">
                <div className="text-xs font-semibold text-emerald-700 uppercase tracking-wider">Normal Traffic</div>
                <div className="text-2xl font-black text-emerald-700 mt-1">{result.normal_traffic}</div>
                <div className="text-[0.65rem] text-slate-500 mt-0.5">Verified clean</div>
              </CardContent>
            </Card>

            <Card className="border-red-200 bg-red-50/20">
              <CardContent className="p-4">
                <div className="text-xs font-semibold text-red-700 uppercase tracking-wider">Anomalies Flagged</div>
                <div className="text-2xl font-black text-red-700 mt-1">{result.anomalies_detected}</div>
                <div className="text-[0.65rem] text-slate-500 mt-0.5">Model predictions</div>
              </CardContent>
            </Card>

            <Card className="border-indigo-200 bg-indigo-50/20">
              <CardContent className="p-4">
                <div className="text-xs font-semibold text-indigo-700 uppercase tracking-wider">Triaged Alerts</div>
                <div className="text-2xl font-black text-indigo-700 mt-1">{result.triaged_alerts}</div>
                <div className="text-[0.65rem] text-slate-500 mt-0.5">Dispatched to SOC Feed</div>
              </CardContent>
            </Card>
          </div>

          {/* Generated Alerts Table (Requirement 5) */}
          <Card className="border-slate-200 bg-white">
            <CardHeader className="pb-3 flex flex-row items-center justify-between">
              <div>
                <CardTitle className="text-sm font-bold text-slate-900">
                  Triaged Dataset Alerts ({result.alerts.length})
                </CardTitle>
                <CardDescription className="text-xs text-slate-500">
                  Events processed through the same ML detection + LLM triage pipeline as live traffic.
                </CardDescription>
              </div>
              {onViewLiveFeed && (
                <Button
                  size="xs"
                  variant="outline"
                  onClick={onViewLiveFeed}
                  className="text-xs text-blue-600 border-blue-200 hover:bg-blue-50"
                >
                  Inspect in Live Feed &rarr;
                </Button>
              )}
            </CardHeader>
            <CardContent>
              {result.alerts.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-500 bg-slate-50 rounded-lg border border-slate-200">
                  No anomalous alerts were triggered for the processed sample rows. All traffic was classified as normal.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-200 bg-slate-50/75 text-slate-600 font-semibold">
                        <th className="py-2 px-3">Row</th>
                        <th className="py-2 px-3">Source IP</th>
                        <th className="py-2 px-3">Prediction</th>
                        <th className="py-2 px-3">Confidence</th>
                        <th className="py-2 px-3">Severity</th>
                        <th className="py-2 px-3">Risk Score</th>
                        <th className="py-2 px-3">Action</th>
                        <th className="py-2 px-3">LLM Triage Summary</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {result.alerts.map((alert, idx) => {
                        const sev = alert.severity || "Medium";
                        const sevBadge =
                          sev === "High" || sev === "Critical"
                            ? "bg-red-50 text-red-700 border-red-200"
                            : sev === "Medium"
                            ? "bg-amber-50 text-amber-700 border-amber-200"
                            : "bg-emerald-50 text-emerald-700 border-emerald-200";

                        return (
                          <tr key={alert.event_id || idx} className="hover:bg-slate-50/50 transition-colors">
                            <td className="py-2.5 px-3 font-mono text-slate-500">#{alert.row_index}</td>
                            <td className="py-2.5 px-3 font-mono text-slate-700 font-semibold text-[0.72rem]">
                              {alert.source_ip || "—"}
                              {alert.source_port ? (
                                <span className="text-slate-400 font-normal">:{alert.source_port}</span>
                              ) : null}
                            </td>
                            <td className="py-2.5 px-3">
                              <span className="px-2 py-0.5 rounded-full text-[0.65rem] font-semibold uppercase bg-red-50 text-red-700 border border-red-200">
                                {alert.prediction}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 font-mono text-slate-700">
                              {(alert.confidence * 100).toFixed(1)}%
                            </td>
                            <td className="py-2.5 px-3">
                              <span className={`px-2 py-0.5 rounded-full text-[0.65rem] font-semibold border ${sevBadge}`}>
                                {sev}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 font-bold text-slate-800">
                              {alert.risk_score != null ? `${alert.risk_score} / 100` : "—"}
                            </td>
                            <td className="py-2.5 px-3 font-mono text-[0.7rem] text-slate-600">
                              {alert.recommended_action || "flag_for_review"}
                            </td>
                            <td className="py-2.5 px-3 text-slate-600 max-w-xs truncate" title={alert.triage_summary || ""}>
                              {alert.triage_summary || "Anomalous network connection requiring review."}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
