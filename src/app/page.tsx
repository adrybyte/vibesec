'use client';

import React, { useState } from 'react';
import { 
  ShieldAlert, 
  GitBranch,
  Terminal, 
  KeyRound, 
  BotMessageSquare, 
  AlertTriangle, 
  Lock,
  ArrowRight,
  Globe,
  Sparkles,
  Copy,
  Check,
  Layers,
  Database,
  CheckCircle2,
  RefreshCw,
  XCircle,
  ShieldCheck,
  Link2,
  FileCode2
} from 'lucide-react';

type Lang = 'es' | 'en';

// ---------- Tipos espejo de la respuesta de /api/scan ----------

type Severity = 'CRÍTICA' | 'ALTA' | 'MEDIA';

interface ApiFinding {
  id: string;
  type: string;
  severity: Severity;
  category: string;
  fileName: string;
  maskedSecret: string;
  rawLineSnippet: string;
  lineNumber: number;
  recommendation: { es: string; en: string };
}

interface ScanReport {
  targetUrl: string;
  mode?: 'repo' | 'file';
  repo?: string | null;
  branch?: string | null;
  fileName: string;
  filesScanned?: { fileName: string; url?: string; status: number; lines: number }[];
  scanTimestamp: string;
  linesScanned: number;
  isSecure: boolean;
  score: number;
  summary: { totalFindings: number; critical: number; high: number };
  findings: ApiFinding[];
}

// ---------- Tipos espejo de la respuesta de /api/fuzz ----------

interface FuzzAttempt {
  id: string;
  label: string;
  payload: string;
  attempted: boolean;
  reachable: boolean;
  status: number | null;
  latencyMs: number;
  bypassed: boolean;
  error?: string;
  responseSnippet: string;
}

interface FuzzReport {
  endpointUrl: string;
  verdict: 'Vulnerable' | 'Segura' | 'Error';
  isVulnerable: boolean;
  payloadsTested: number;
  payloadsReached: number;
  totalCombinations?: number;
  requestsSent?: number;
  successfulPayload: string | null;
  successfulPayloadId: string | null;
  successfulPayloadLabel: string | null;
  successfulFormat?: string | null;
  failedRequests: number;
  durationMs: number;
  timestamp: string;
  canary: string;
  results: FuzzAttempt[];
}

type ModuleStatus = 'idle' | 'loading' | 'done' | 'error';

// ---------- Estilos e iconos por severidad / tipo de hallazgo ----------

const SEVERITY_STYLES: Record<
  Severity,
  {
    border: string;
    iconBox: string;
    badge: string;
    category: string;
    snippet: string;
  }
> = {
  'CRÍTICA': {
    border: 'border-zinc-800 hover:border-rose-400/30',
    iconBox: 'bg-rose-400/5 border-rose-400/15 text-rose-400',
    badge: 'bg-rose-400/10 text-rose-300 border-rose-400/20',
    category: 'text-rose-400',
    snippet: 'text-rose-400'
  },
  'ALTA': {
    border: 'border-zinc-800 hover:border-amber-400/30',
    iconBox: 'bg-amber-400/5 border-amber-400/15 text-amber-400',
    badge: 'bg-amber-400/10 text-amber-300 border-amber-400/20',
    category: 'text-amber-400',
    snippet: 'text-amber-400'
  },
  'MEDIA': {
    border: 'border-zinc-800 hover:border-zinc-700',
    iconBox: 'bg-zinc-800/60 border-zinc-700 text-zinc-300',
    badge: 'bg-zinc-800 text-zinc-300 border-zinc-700',
    category: 'text-zinc-400',
    snippet: 'text-zinc-300'
  }
};

function FindingIcon({ type, className }: { type: string; className?: string }) {
  if (type.includes('OpenAI')) return <KeyRound className={className} />;
  if (type.includes('GitHub')) return <GitBranch className={className} />;
  if (type.includes('Database')) return <Database className={className} />;
  return <Lock className={className} />;
}

/** Añade esquema si el usuario escribe un endpoint sin http(s):// */
function normalizeEndpoint(value: string): string {
  const v = value.trim();
  if (!v) return '';
  if (v.startsWith('/')) return v;
  if (/^https?:\/\//i.test(v)) return v;
  if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?(\/|$)/i.test(v)) {
    return `http://${v}`;
  }
  return `https://${v}`;
}

/** Añade esquema a la URL del repositorio si el usuario lo omite. */
function normalizeRepoInput(value: string): string {
  const v = value.trim();
  if (!v) return '';
  if (v.startsWith('/')) return v;
  if (/^https?:\/\//i.test(v)) return v;
  return `https://${v}`;
}

const content = {
  es: {
    nav: {
      badge: 'Escáner v1.3 Beta Activo',
      features: 'Módulos',
      pricing: 'Precios',
      docs: 'Reglas OWASP GenAI',
      connect: 'Conectar GitHub'
    },
    hero: {
      tag: 'Seguridad Especializada en GenAI & Vibe Coding',
      title1: 'Protege tus microapps de IA con',
      title2: 'VibeSec',
      description: 'El código escrito a la velocidad de la luz por Cursor, v0 o Bolt suele omitir controles elementales. Audita repositorios contra API keys filtradas y endpoints contra Prompt Injections (OWASP Top 10 for LLMs).',
      sampleRepo: 'Demo:',
      ctaDemo: 'Cargar demo completa',
      ctaDemoRepo: 'Solo repo',
      ctaDemoEndpoint: 'Solo endpoint'
    },
    inputs: {
      repoLabel: 'URL del Repositorio (Gist/GitHub crudo) para buscar secretos',
      repoPlaceholder: 'https://raw.githubusercontent.com/usuario/repo/main/.env',
      repoHint: 'Archivo crudo, enlace /blob/ o la raíz del repo (.env, .env.local, next.config.ts/js).',
      endpointLabel: 'Endpoint de la IA para testear Inyecciones',
      endpointPlaceholder: 'https://tu-microapp.com/api/chat',
      endpointHint: 'Se enviarán payloads JSON con los campos message, prompt y text.',
      requiredHint: 'Rellena al menos uno de los dos campos para poder escanear.',
      scanBtn: 'Escanear Vulnerabilidades',
      scanningBtn: 'Escaneando...',
      clear: 'Limpiar'
    },
    metrics: [
      { value: '4.8s', label: 'Tiempo prom. de escaneo' },
      { value: '9', label: 'Combinaciones por endpoint' },
      { value: '99.4%', label: 'Precisión en detección de secretos' },
      { value: 'OWASP', label: 'Alineado al Top 10 LLM' }
    ],
    report: {
      title: 'Reporte de Seguridad Generado',
      targetLabel: 'Objetivo auditado:',
      fileLabel: 'Archivo:',
      lineLabel: 'Línea',
      criticalBadge: 'Vulnerabilidad Crítica',
      highBadge: 'Riesgo Alto',
      findingsBadge: 'Hallazgos',
      riskScore: 'Puntaje de Seguridad',
      secureTitle: 'Código Limpio: No se expusieron secretos',
      secureDesc: 'No se detectaron secretos expuestos ni patrones de riesgo en el código analizado. Sigue usando un gestor de secretos y rota claves periódicamente.',
      secureNoFilesDesc: 'No se encontraron archivos críticos públicos (.env, .env.local, next.config) en las ramas main/master. El repositorio no expone secretos en esos archivos.',
      secureBothDesc: 'No se detectaron secretos expuestos y el endpoint resistió todos los payloads de prompt injection.',
      errorTitle: 'No se pudo completar el escaneo',
      mitigationHeader: 'Mitigación Recomendada:',
      emptyFindings: 'Sin hallazgos registrados.',
      scannedLines: 'Líneas analizadas:',
      filesLabel: 'Archivos analizados:',
      branchLabel: 'Rama:',
      reScan: 'Volver a Escanear',
      demoNotice: 'Este es un informe real generado por el escáner local.'
    },
    severityLabels: {
      'CRÍTICA': 'SEVERIDAD: CRÍTICA',
      'ALTA': 'SEVERIDAD: ALTA',
      'MEDIA': 'SEVERIDAD: MEDIA'
    },
    fuzz: {
      badge: 'MÓDULO 2 · FUZZER',
      cardTitle: 'Inyección de Prompts',
      cardDesc: 'Se enviaron payloads maliciosos al endpoint de la microapp para comprobar si el modelo obedece instrucciones del usuario.',
      vulnerableBadge: 'VULNERABLE',
      secureBadge: 'SEGURA',
      vulnerableTitle: 'El endpoint obedeció una inyección',
      vulnerableDesc: 'La microapp devolvió el canario VIBESEC_BYPASS, confirmando que las instrucciones del usuario pueden anular el system prompt.',
      secureTitle: 'El endpoint resistió los ataques',
      secureDesc: 'Ninguno de los payloads probados logró anular las instrucciones del sistema.',
      payloadLabel: 'Payload exitoso:',
      endpointLabel: 'Endpoint atacado:',
      responseLabel: 'Respuesta del objetivo:',
      testedLabel: 'Payloads probados:',
      latencyLabel: 'Duración:',
      testedAttempts: 'Intentos:',
      moduleError: 'El módulo de Prompt Injection no pudo ejecutarse',
      retry: 'Reintentar módulo',
      unavailable: 'Módulo no ejecutado',
      mitigationVulnerable: 'Aísla la entrada del usuario con delimitadores (XML/Markdown), aplica guardrails semánticos y nunca confíes en el contenido del mensaje como instrucción.',
      mitigationSecure: 'Mantén el endurecimiento: validación de entrada, delimitadores explícitos y pruebas de regresión de prompt injection en CI.'
    },
    featuresSection: {
      heading: 'Por qué auditar código generado por IA',
      subheading: 'Las IAs programan rápido, pero suelen repetir patrones inseguros de repositorios públicos obsoletos.',
      f1_title: 'Detección de Secrets & Webhooks',
      f1_desc: 'Identifica API keys de OpenAI, Anthropic, Replicate, Stripe y Supabase antes de ir a producción.',
      f2_title: 'Pruebas de Fuga de Prompt',
      f2_desc: 'Simulamos ataques automatizados tipo Jailbreak para comprobar si tu agente revela lógica propietaria.',
      f3_title: 'Integración CI/CD Lista',
      f3_desc: 'Ejecuta VibeSec como GitHub Action y bloquea PRs con vulnerabilidades en tus proyectos Vibe Coding.'
    },
    footer: {
      copyright: '© 2026 VibeSec Inc. Seguridad proactiva para la era del Vibe Coding.',
      status: 'Todos los sistemas operativos'
    }
  },
  en: {
    nav: {
      badge: 'Scanner v1.3 Beta Live',
      features: 'Modules',
      pricing: 'Pricing',
      docs: 'OWASP GenAI Rules',
      connect: 'Connect GitHub'
    },
    hero: {
      tag: 'GenAI & Vibe Coding Security Intelligence',
      title1: 'Secure your AI-generated microapps with',
      title2: 'VibeSec',
      description: 'Code written at lightning speed by Cursor, v0, or Bolt frequently skips security basics. Audit repositories for leaked API keys and endpoints for Prompt Injections (OWASP Top 10 for LLMs).',
      sampleRepo: 'Demo:',
      ctaDemo: 'Load full demo',
      ctaDemoRepo: 'Repo only',
      ctaDemoEndpoint: 'Endpoint only'
    },
    inputs: {
      repoLabel: 'Repository URL (Gist/raw GitHub) to scan for secrets',
      repoPlaceholder: 'https://raw.githubusercontent.com/user/repo/main/.env',
      repoHint: 'Raw file, /blob/ link, or the repo root (.env, .env.local, next.config.ts/js).',
      endpointLabel: 'AI endpoint to test for Injections',
      endpointPlaceholder: 'https://your-microapp.com/api/chat',
      endpointHint: 'JSON payloads will be sent with the message, prompt and text fields.',
      requiredHint: 'Fill in at least one of the two fields to scan.',
      scanBtn: 'Scan Vulnerabilities',
      scanningBtn: 'Scanning...',
      clear: 'Clear'
    },
    metrics: [
      { value: '4.8s', label: 'Average scan time' },
      { value: '9', label: 'Combinations per endpoint' },
      { value: '99.4%', label: 'Secret detection accuracy' },
      { value: 'OWASP', label: 'Aligned with LLM Top 10' }
    ],
    report: {
      title: 'Generated Security Report',
      targetLabel: 'Target inspected:',
      fileLabel: 'File:',
      lineLabel: 'Line',
      criticalBadge: 'Critical Vulnerability',
      highBadge: 'High Risk',
      findingsBadge: 'Findings',
      riskScore: 'Security Score',
      secureTitle: 'Clean Code: No secrets exposed',
      secureDesc: 'No exposed secrets or risky patterns were detected in the scanned code. Keep using a secret manager and rotate keys regularly.',
      secureNoFilesDesc: 'No public critical files (.env, .env.local, next.config) were found on the main/master branches. The repository does not expose secrets in those files.',
      secureBothDesc: 'No exposed secrets were found and the endpoint resisted every prompt injection payload.',
      errorTitle: 'The scan could not be completed',
      mitigationHeader: 'Recommended Mitigation:',
      emptyFindings: 'No findings recorded.',
      scannedLines: 'Lines scanned:',
      filesLabel: 'Files scanned:',
      branchLabel: 'Branch:',
      reScan: 'Scan Again',
      demoNotice: 'This is a real report generated by the local scanner.'
    },
    severityLabels: {
      'CRÍTICA': 'SEVERITY: CRITICAL',
      'ALTA': 'SEVERITY: HIGH',
      'MEDIA': 'SEVERITY: MEDIUM'
    },
    fuzz: {
      badge: 'MODULE 2 · FUZZER',
      cardTitle: 'Prompt Injection',
      cardDesc: 'Malicious payloads were sent to the microapp endpoint to check whether the model obeys user instructions.',
      vulnerableBadge: 'VULNERABLE',
      secureBadge: 'SECURE',
      vulnerableTitle: 'The endpoint obeyed an injection',
      vulnerableDesc: 'The microapp returned the VIBESEC_BYPASS canary, confirming that user instructions can override the system prompt.',
      secureTitle: 'The endpoint resisted the attacks',
      secureDesc: 'None of the tested payloads managed to override the system instructions.',
      payloadLabel: 'Successful payload:',
      endpointLabel: 'Target endpoint:',
      responseLabel: 'Target response:',
      testedLabel: 'Payloads tested:',
      latencyLabel: 'Duration:',
      testedAttempts: 'Attempts:',
      moduleError: 'The Prompt Injection module could not run',
      retry: 'Retry module',
      unavailable: 'Module not executed',
      mitigationVulnerable: 'Isolate user input with delimiters (XML/Markdown), apply semantic guardrails, and never treat message content as an instruction.',
      mitigationSecure: 'Keep the hardening in place: input validation, explicit delimiters, and prompt injection regression tests in CI.'
    },
    featuresSection: {
      heading: 'Why audit AI-generated codebases',
      subheading: 'AI assistants code blazingly fast, but frequently reproduce outdated or insecure boilerplate patterns.',
      f1_title: 'Secrets & Webhook Detection',
      f1_desc: 'Identify OpenAI, Anthropic, Replicate, Stripe, and Supabase credentials before deployment.',
      f2_title: 'Prompt Leakage Tests',
      f2_desc: 'Automated simulated jailbreak attacks to ensure your agents do not leak proprietary IP or logic.',
      f3_title: 'CI/CD Ready Integration',
      f3_desc: 'Run VibeSec as a GitHub Action and block vulnerable PRs inside your Vibe Coding workflow.'
    },
    footer: {
      copyright: '© 2026 VibeSec Inc. Proactive security for the Vibe Coding era.',
      status: 'All systems operational'
    }
  }
};

export default function VibeSecApp() {
  const [lang, setLang] = useState<Lang>('es');
  const [repoUrl, setRepoUrl] = useState('');
  const [endpointUrl, setEndpointUrl] = useState('');

  const [scanStatus, setScanStatus] = useState<ModuleStatus>('idle');
  const [report, setReport] = useState<ScanReport | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const [fuzzStatus, setFuzzStatus] = useState<ModuleStatus>('idle');
  const [fuzzReport, setFuzzReport] = useState<FuzzReport | null>(null);
  const [fuzzError, setFuzzError] = useState<string | null>(null);

  const [copiedId, setCopiedId] = useState<string | null>(null);

  const t = content[lang];
  const isScanning = scanStatus === 'loading' || fuzzStatus === 'loading';
  const canScan = repoUrl.trim().length > 0 || endpointUrl.trim().length > 0;
  const hasAnyResult = scanStatus === 'done' || fuzzStatus === 'done';

  const anyRequested = scanStatus !== 'idle' || fuzzStatus !== 'idle';
  const allRequestedFailed =
    anyRequested &&
    !isScanning &&
    !hasAnyResult &&
    (scanStatus === 'error' || scanStatus === 'idle') &&
    (fuzzStatus === 'error' || fuzzStatus === 'idle');

  const allClean =
    scanStatus === 'done' &&
    fuzzStatus === 'done' &&
    report?.isSecure === true &&
    fuzzReport?.isVulnerable === false;

  const scanSecrets = async (targetUrl: string): Promise<void> => {
    setScanStatus('loading');
    setReport(null);
    setScanError(null);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl })
      });
      const data = await response.json().catch(() => null);

      if (!response.ok) {
        setScanError(
          (data && typeof data.error === 'string' && data.error) ||
            `Error inesperado del servidor (HTTP ${response.status}).`
        );
        setScanStatus('error');
        return;
      }

      setReport(data as ScanReport);
      setScanStatus('done');
    } catch {
      setScanError(
        lang === 'es'
          ? 'No se pudo contactar con el servidor de escaneo.'
          : 'Could not reach the scanning server.'
      );
      setScanStatus('error');
    }
  };

  const fuzzEndpoint = async (target: string): Promise<void> => {
    setFuzzStatus('loading');
    setFuzzReport(null);
    setFuzzError(null);

    try {
      const response = await fetch('/api/fuzz', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ endpointUrl: target })
      });
      const data = await response.json().catch(() => null);

      if (!response.ok) {
        setFuzzError(
          (data && typeof data.error === 'string' && data.error) ||
            `Error inesperado del fuzzer (HTTP ${response.status}).`
        );
        setFuzzStatus('error');
        return;
      }

      setFuzzReport(data as FuzzReport);
      setFuzzStatus('done');
    } catch {
      setFuzzError(
        lang === 'es'
          ? 'No se pudo contactar con el fuzzer.'
          : 'Could not reach the fuzzer.'
      );
      setFuzzStatus('error');
    }
  };

  const runScan = async (
    repo: string = repoUrl,
    endpoint: string = endpointUrl
  ): Promise<void> => {
    const hasRepo = repo.trim().length > 0;
    const hasEndpoint = endpoint.trim().length > 0;
    if (!hasRepo && !hasEndpoint) return;

    const tasks: Promise<void>[] = [];

    if (hasRepo) {
      tasks.push(scanSecrets(normalizeRepoInput(repo)));
    } else {
      setScanStatus('idle');
      setReport(null);
      setScanError(null);
    }

    if (hasEndpoint) {
      tasks.push(fuzzEndpoint(normalizeEndpoint(endpoint)));
    } else {
      setFuzzStatus('idle');
      setFuzzReport(null);
      setFuzzError(null);
    }

    await Promise.all(tasks);
  };

  const handleScan = (e: React.FormEvent) => {
    e.preventDefault();
    void runScan();
  };

  const handleDemo = (mode: 'full' | 'repo' | 'endpoint') => {
    const demoRepo = '/api/demo/leaky-config';
    const demoEndpoint = `${window.location.origin}/api/victim`;

    const repo = mode === 'endpoint' ? '' : demoRepo;
    const endpoint = mode === 'repo' ? '' : demoEndpoint;

    setRepoUrl(repo);
    setEndpointUrl(endpoint);
    void runScan(repo, endpoint);
  };

  const handleClear = () => {
    setRepoUrl('');
    setEndpointUrl('');
    setScanStatus('idle');
    setReport(null);
    setScanError(null);
    setFuzzStatus('idle');
    setFuzzReport(null);
    setFuzzError(null);
  };

  const handleCopySnippet = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const scoreColor =
    !report || report.score >= 80
      ? 'bg-emerald-400/5 text-emerald-400 border-emerald-400/15'
      : report.score >= 50
        ? 'bg-amber-400/5 text-amber-400 border-amber-400/15'
        : 'bg-rose-400/5 text-rose-400 border-rose-400/15';

  const totalCards = (report?.findings.length ?? 0) + (fuzzReport ? 1 : 0);

  return (
    <div className="min-h-screen bg-[#141414] text-zinc-300 selection:bg-emerald-400/20 selection:text-emerald-200 font-mono antialiased overflow-x-hidden">

      {/* Barra de Navegación */}
      <nav className="relative z-20 border-b border-zinc-800 bg-[#141414]/90 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-center">
              <ShieldAlert className="w-5 h-5 text-emerald-400" />
            </div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-xl tracking-tight text-zinc-100">VibeSec</span>
              <span className="inline-flex items-center gap-1.5 text-[10px] font-mono font-medium px-2 py-0.5 rounded-md border border-zinc-800 bg-zinc-900/50 text-zinc-500">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                {t.nav.badge}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Selector de Idioma */}
            <div className="flex items-center bg-zinc-900/50 border border-zinc-800 rounded-lg p-1 text-xs font-mono">
              <Globe className="w-3.5 h-3.5 text-zinc-500 ml-1.5 mr-1" />
              <button
                type="button"
                onClick={() => setLang('es')}
                className={`px-2 py-1 rounded-md transition-colors cursor-pointer ${
                  lang === 'es'
                    ? 'bg-zinc-800 text-emerald-400 font-semibold'
                    : 'text-zinc-500 hover:text-zinc-300'
                }`}
              >
                ES
              </button>
              <button
                type="button"
                onClick={() => setLang('en')}
                className={`px-2 py-1 rounded-md transition-colors cursor-pointer ${
                  lang === 'en'
                    ? 'bg-zinc-800 text-emerald-400 font-semibold'
                    : 'text-zinc-500 hover:text-zinc-300'
                }`}
              >
                EN
              </button>
            </div>

            <a
              href="https://github.com"
              target="_blank"
              rel="noreferrer"
              className="hidden sm:inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg border border-zinc-800 bg-zinc-900/40 hover:bg-zinc-900 hover:border-zinc-700 text-xs font-medium text-zinc-400 hover:text-zinc-200 transition-colors"
            >
              <GitBranch className="w-4 h-4 text-emerald-400" />
              <span>{t.nav.connect}</span>
            </a>
          </div>
        </div>
      </nav>

      {/* Contenido Principal */}
      <main className="relative z-10 max-w-5xl mx-auto px-6 pt-16 pb-24 flex flex-col items-center">
        {/* Tag Superior */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg border border-zinc-800 bg-zinc-900/40 text-zinc-400 text-xs font-mono tracking-wide mb-8">
          <Sparkles className="w-3.5 h-3.5 animate-pulse text-emerald-400" />
          <span>{t.hero.tag}</span>
        </div>

        {/* Título & Hero Copy */}
        <header className="text-center max-w-3xl mb-10">
          <h1 className="text-4xl sm:text-6xl font-bold tracking-tight text-zinc-100 mb-6 leading-tight">
            {t.hero.title1}{' '}
            <span className="text-emerald-400">{t.hero.title2}</span>
          </h1>
          <p className="text-base sm:text-lg text-zinc-400 leading-relaxed max-w-2xl mx-auto">
            {t.hero.description}
          </p>
        </header>

        {/* Formulario de Escaneo (dos módulos) */}
        <div className="w-full max-w-2xl mb-6">
          <form
            onSubmit={handleScan}
            className="p-4 bg-zinc-900/50 border border-zinc-800 rounded-xl backdrop-blur-sm focus-within:border-zinc-700 transition-colors space-y-4"
          >
            {/* Input 1: repositorio */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3 focus-within:border-zinc-700 transition-colors">
              <label htmlFor="repo-url" className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-widest text-zinc-500 mb-2">
                <FileCode2 className="w-3.5 h-3.5 text-emerald-400" />
                {t.inputs.repoLabel}
              </label>
              <div className="flex items-center gap-2">
                <span className="text-sm text-emerald-400/80 select-none shrink-0">~$</span>
                <input
                  id="repo-url"
                  type="text"
                  inputMode="url"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder={t.inputs.repoPlaceholder}
                  disabled={isScanning}
                  className="w-full py-1.5 bg-transparent text-sm text-zinc-200 placeholder:text-zinc-600 outline-none font-mono disabled:opacity-50"
                />
              </div>
              <p className="text-[10px] text-zinc-600 font-mono mt-1.5">{t.inputs.repoHint}</p>
            </div>

            {/* Input 2: endpoint de IA */}
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-3 focus-within:border-zinc-700 transition-colors">
              <label htmlFor="endpoint-url" className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-widest text-zinc-500 mb-2">
                <Link2 className="w-3.5 h-3.5 text-zinc-400" />
                {t.inputs.endpointLabel}
              </label>
              <div className="flex items-center gap-2">
                <span className="text-sm text-emerald-400/80 select-none shrink-0">&#62;_</span>
                <input
                  id="endpoint-url"
                  type="text"
                  inputMode="url"
                  value={endpointUrl}
                  onChange={(e) => setEndpointUrl(e.target.value)}
                  placeholder={t.inputs.endpointPlaceholder}
                  disabled={isScanning}
                  className="w-full py-1.5 bg-transparent text-sm text-zinc-200 placeholder:text-zinc-600 outline-none font-mono disabled:opacity-50"
                />
              </div>
              <p className="text-[10px] text-zinc-600 font-mono mt-1.5">{t.inputs.endpointHint}</p>
            </div>

            {/* Acciones */}
            <div className="flex flex-col gap-3 pt-1">
              <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
                <span className="text-zinc-600">{t.hero.sampleRepo}</span>
                <button
                  type="button"
                  onClick={() => handleDemo('full')}
                  disabled={isScanning}
                  className="text-emerald-400 hover:text-emerald-300 font-medium transition-colors cursor-pointer disabled:opacity-50"
                >
                  {t.hero.ctaDemo}
                </button>
                <span className="text-zinc-700">·</span>
                <button
                  type="button"
                  onClick={() => handleDemo('repo')}
                  disabled={isScanning}
                  className="text-zinc-500 hover:text-zinc-200 transition-colors cursor-pointer disabled:opacity-50"
                >
                  {t.hero.ctaDemoRepo}
                </button>
                <span className="text-zinc-700">·</span>
                <button
                  type="button"
                  onClick={() => handleDemo('endpoint')}
                  disabled={isScanning}
                  className="text-zinc-500 hover:text-zinc-200 transition-colors cursor-pointer disabled:opacity-50"
                >
                  {t.hero.ctaDemoEndpoint}
                </button>
              </div>

              <div className="flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={handleClear}
                  disabled={isScanning || (!repoUrl && !endpointUrl && !hasAnyResult)}
                  className="px-3 py-2.5 text-xs font-mono text-zinc-500 hover:text-zinc-200 disabled:opacity-40 disabled:cursor-not-allowed transition-colors cursor-pointer"
                >
                  {t.inputs.clear}
                </button>
                <button
                  type="submit"
                  disabled={!canScan || isScanning}
                  className="flex-1 sm:flex-none px-5 py-2.5 bg-emerald-400/10 hover:bg-emerald-400/15 border border-emerald-400/30 disabled:bg-zinc-900 disabled:text-zinc-600 disabled:border-zinc-800 disabled:cursor-not-allowed text-emerald-300 font-medium text-sm rounded-lg transition-colors flex items-center justify-center gap-2 cursor-pointer"
                >
                  {isScanning ? (
                    <>
                      <div className="w-4 h-4 border-2 border-emerald-300 border-t-transparent rounded-full animate-spin" />
                      <span>{t.inputs.scanningBtn}</span>
                    </>
                  ) : (
                    <>
                      <span>{t.inputs.scanBtn}</span>
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </div>
            </div>

            {!canScan && (
              <p className="text-[11px] text-amber-400/80 font-mono flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                {t.inputs.requiredHint}
              </p>
            )}
          </form>

          <div className="flex items-center justify-end text-xs text-zinc-500 mt-3 px-2 font-mono">
            <span className="flex items-center gap-1.5 text-zinc-500">
              <Lock className="w-3 h-3 text-emerald-400" /> {lang === 'es' ? 'Análisis en memoria & zero logs' : 'In-memory analysis & zero logs'}
            </span>
          </div>
        </div>

        {/* Métricas destacadas */}
        <div className="w-full max-w-3xl grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 mb-16">
          {t.metrics.map((m, idx) => (
            <div key={idx} className="p-4 rounded-lg bg-zinc-900/40 border border-zinc-800 text-center">
              <div className="text-2xl font-medium font-mono text-emerald-400">
                {m.value}
              </div>
              <div className="text-[10px] text-zinc-500 mt-1 uppercase tracking-widest font-mono">
                {m.label}
              </div>
            </div>
          ))}
        </div>

        {/* ==================== RESULTADOS ==================== */}

        {/* Estado: escaneando */}
        {isScanning && (
          <div className="w-full max-w-4xl space-y-4">
            <div className="p-5 rounded-xl bg-zinc-900/50 border border-zinc-800 flex items-center gap-4">
              <div className="w-9 h-9 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-center shrink-0">
                <RefreshCw className="w-4 h-4 text-emerald-400 animate-spin" />
              </div>
              <div className="flex-1">
                <p className="text-sm font-semibold text-zinc-200">{t.inputs.scanningBtn}</p>
                <p className="text-[11px] text-zinc-500 font-mono mt-0.5">
                  {[scanStatus === 'loading' ? '/api/scan' : null, fuzzStatus === 'loading' ? '/api/fuzz' : null]
                    .filter(Boolean)
                    .join(' + ')}
                </p>
                <div className="h-1 w-full bg-zinc-800 rounded-full mt-2 overflow-hidden">
                  <div className="h-full w-1/3 bg-emerald-400/50 rounded-full animate-pulse" />
                </div>
              </div>
            </div>
            <div className="grid md:grid-cols-2 gap-6">
              {[0, 1].map((i) => (
                <div key={i} className="p-6 rounded-xl bg-zinc-900/40 border border-zinc-800 animate-pulse space-y-4">
                  <div className="h-10 w-10 rounded-lg bg-zinc-800/70" />
                  <div className="h-3 w-2/3 rounded bg-zinc-800/70" />
                  <div className="h-3 w-1/2 rounded bg-zinc-800/70" />
                  <div className="h-20 w-full rounded-lg bg-zinc-800/40" />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Estado: todos los módulos solicitados fallaron */}
        {allRequestedFailed && (
          <div className="w-full max-w-4xl p-6 rounded-xl bg-zinc-900/50 border border-zinc-800">
            <div className="flex items-start gap-3">
              <div className="p-2.5 rounded-lg bg-rose-400/5 border border-rose-400/15 text-rose-400 shrink-0">
                <XCircle className="w-5 h-5" />
              </div>
              <div className="flex-1 space-y-1">
                <h3 className="text-base font-semibold text-zinc-100">{t.report.errorTitle}</h3>
                {scanStatus === 'error' && (
                  <p className="text-xs text-rose-400/90 font-mono break-words">
                    <span className="font-semibold">/api/scan:</span> {scanError}
                  </p>
                )}
                {fuzzStatus === 'error' && (
                  <p className="text-xs text-rose-400/90 font-mono break-words">
                    <span className="font-semibold">/api/fuzz:</span> {fuzzError}
                  </p>
                )}
              </div>
            </div>
            <button
              type="button"
              onClick={() => void runScan()}
              className="mt-4 inline-flex items-center gap-2 px-4 py-2 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-xs font-medium text-zinc-300 rounded-lg transition-colors cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5 text-emerald-400" />
              {t.report.reScan}
            </button>
          </div>
        )}

        {/* Estado: hay al menos un módulo con resultado */}
        {hasAnyResult && (
          <div className="w-full max-w-4xl space-y-6">
            {/* Header del Reporte */}
            <div className="p-5 rounded-xl bg-zinc-900/50 border border-zinc-800 flex flex-col gap-4">
              <div className="space-y-1 min-w-0">
                <div className="flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-emerald-400 shrink-0" />
                  <h3 className="text-lg font-semibold text-zinc-100">{t.report.title}</h3>
                </div>
                {report && (
                  <p className="text-xs text-zinc-500 font-mono break-all">
                    {t.report.targetLabel}{' '}
                    <span className="text-emerald-400/90">{report.targetUrl}</span>
                  </p>
                )}
                {fuzzReport && (
                  <p className="text-xs text-zinc-500 font-mono break-all">
                    {t.fuzz.endpointLabel}{' '}
                    <span className="text-zinc-300">{fuzzReport.endpointUrl}</span>
                  </p>
                )}
                {report && (
                  <p className="text-[11px] text-zinc-500 font-mono">
                    {t.report.fileLabel} <span className="text-zinc-300">{report.fileName}</span>
                    {' · '}
                    {t.report.scannedLines} <span className="text-zinc-300">{report.linesScanned}</span>
                  </p>
                )}
                {report?.mode === 'repo' && report.filesScanned && report.filesScanned.length > 0 && (
                  <p className="text-[11px] text-zinc-500 font-mono break-all">
                    {t.report.filesLabel}{' '}
                    <span className="text-zinc-300">
                      {report.filesScanned.map((f) => f.fileName).join(', ')}
                    </span>
                    {report.branch ? (
                      <>
                        {' · '}
                        {t.report.branchLabel} <span className="text-zinc-300">{report.branch}</span>
                      </>
                    ) : null}
                  </p>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2.5">
                {report && (
                  <>
                    <span
                      className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border font-mono ${
                        report.isSecure
                          ? 'bg-emerald-400/5 text-emerald-400 border-emerald-400/15'
                          : 'bg-rose-400/5 text-rose-400 border-rose-400/15'
                      }`}
                    >
                      <AlertTriangle className="w-3.5 h-3.5" />
                      {t.report.findingsBadge}: {report.summary.totalFindings}
                    </span>
                    <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border font-mono ${scoreColor}`}>
                      {t.report.riskScore}: {report.score}/100
                    </span>
                  </>
                )}
                {fuzzReport && (
                  <span
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border font-mono ${
                      fuzzReport.isVulnerable
                        ? 'bg-rose-400/5 text-rose-400 border-rose-400/15'
                        : 'bg-emerald-400/5 text-emerald-400 border-emerald-400/15'
                    }`}
                  >
                    <BotMessageSquare className="w-3.5 h-3.5" />
                    {t.fuzz.cardTitle}: {fuzzReport.isVulnerable ? t.fuzz.vulnerableBadge : t.fuzz.secureBadge}
                  </span>
                )}
              </div>
            </div>

            {/* Todo limpio: sin secretos y endpoint seguro */}
            {allClean && (
              <div className="p-8 rounded-xl bg-zinc-900/40 border border-zinc-800 text-center">
                <div className="w-14 h-14 mx-auto rounded-lg bg-emerald-400/5 border border-emerald-400/15 flex items-center justify-center mb-4">
                  <CheckCircle2 className="w-7 h-7 text-emerald-400" />
                </div>
                <h4 className="text-xl font-semibold text-emerald-400 mb-2">{t.report.secureTitle}</h4>
                <p className="text-sm text-zinc-400 max-w-lg mx-auto leading-relaxed">
                  {t.report.secureBothDesc}
                </p>
              </div>
            )}

            {/* Aviso compacto: secretos limpios */}
            {!allClean && report?.isSecure && (
              <div className="p-4 rounded-xl bg-zinc-900/40 border border-zinc-800 flex items-start gap-3">
                <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-semibold text-emerald-400">{t.report.secureTitle}</p>
                  <p className="text-xs text-zinc-400 leading-relaxed">
                    {report.mode === 'repo' && (report.filesScanned?.length ?? 0) === 0
                      ? t.report.secureNoFilesDesc
                      : t.report.secureDesc}
                  </p>
                </div>
              </div>
            )}

            {/* Aviso: el escaneo de secretos falló, pero el fuzzer sí corrió */}
            {scanStatus === 'error' && fuzzStatus === 'done' && (
              <div className="p-4 rounded-xl bg-zinc-900/40 border border-zinc-800 flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-semibold text-amber-400">{t.report.errorTitle}</p>
                  <p className="text-xs text-zinc-400 font-mono break-words">{scanError}</p>
                </div>
              </div>
            )}

            {/* Aviso: el fuzzer falló, pero el escaneo de secretos sí corrió */}
            {fuzzStatus === 'error' && scanStatus === 'done' && (
              <div className="p-4 rounded-xl bg-zinc-900/40 border border-zinc-800 flex items-start gap-3">
                <BotMessageSquare className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-semibold text-amber-400">{t.fuzz.moduleError}</p>
                  <p className="text-xs text-zinc-400 font-mono break-words">{fuzzError}</p>
                </div>
                <button
                  type="button"
                  onClick={() => void fuzzEndpoint(normalizeEndpoint(endpointUrl))}
                  className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-[11px] font-medium text-zinc-300 rounded-lg transition-colors cursor-pointer"
                >
                  <RefreshCw className="w-3 h-3 text-emerald-400" />
                  {t.fuzz.retry}
                </button>
              </div>
            )}

            {/* Grid de resultados: solo los módulos ejecutados */}
            {totalCards > 0 && (
              <div className={`grid gap-6 ${totalCards > 1 ? 'md:grid-cols-2' : ''}`}>
                {/* Tarjetas dinámicas de secretos (solo si se ejecutó /api/scan) */}
                {report?.findings.map((finding) => {
                  const styles = SEVERITY_STYLES[finding.severity] ?? SEVERITY_STYLES['MEDIA'];

                  return (
                    <div
                      key={finding.id}
                      className={`p-6 bg-zinc-900/50 border rounded-xl relative overflow-hidden transition-colors flex flex-col justify-between ${styles.border}`}
                    >
                      <div>
                        <div className="flex items-start justify-between mb-4 gap-2">
                          <div className={`p-2.5 rounded-lg border ${styles.iconBox}`}>
                            <FindingIcon type={finding.type} className="w-5 h-5" />
                          </div>
                          <span
                            className={`text-[10px] font-mono tracking-wider px-2.5 py-1 rounded-md font-medium border text-right ${styles.badge}`}
                          >
                            {t.severityLabels[finding.severity] ?? finding.severity}
                          </span>
                        </div>

                        <span className={`text-[10px] font-mono uppercase tracking-widest block mb-1 ${styles.category}`}>
                          {finding.category}
                        </span>
                        <h4 className="text-lg font-semibold text-zinc-100 mb-2">{finding.type}</h4>

                        <div className="bg-zinc-950/60 border border-zinc-800 rounded-lg p-3 font-mono text-xs text-zinc-300 mb-4">
                          <div className="flex items-center justify-between text-zinc-500 mb-1.5 text-[11px] gap-2">
                            <span className="truncate">
                              {t.report.fileLabel}{' '}
                              <strong className="text-zinc-300 font-medium">{finding.fileName}</strong>
                              {' · '}
                              {t.report.lineLabel} <strong className="text-zinc-300 font-medium">{finding.lineNumber}</strong>
                            </span>
                            <button
                              type="button"
                              onClick={() => handleCopySnippet(finding.id, finding.rawLineSnippet)}
                              className="text-zinc-500 hover:text-zinc-200 transition-colors cursor-pointer shrink-0"
                              title="Copy"
                            >
                              {copiedId === finding.id ? (
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                          <p className={`break-all select-all ${styles.snippet}`}>
                            {finding.rawLineSnippet}
                          </p>
                          <p className="text-[11px] text-zinc-500 mt-1.5 border-t border-zinc-800 pt-1.5">
                            Secret detectado: <span className="text-zinc-300">{finding.maskedSecret}</span>
                          </p>
                        </div>
                      </div>

                      <div className="text-xs text-zinc-400 bg-zinc-950/40 p-3.5 rounded-lg border border-zinc-800">
                        <div className="flex items-center gap-1.5 font-medium text-zinc-200 mb-1">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                          <span>{t.report.mitigationHeader}</span>
                        </div>
                        <p className="leading-relaxed">
                          {lang === 'es' ? finding.recommendation.es : finding.recommendation.en}
                        </p>
                      </div>
                    </div>
                  );
                })}

                {/* Tarjeta dinámica de Prompt Injection (solo si se ejecutó /api/fuzz) */}
                {fuzzReport && (
                  <div
                    className={`p-6 bg-zinc-900/50 border rounded-xl relative overflow-hidden transition-colors flex flex-col justify-between ${
                      fuzzReport.isVulnerable
                        ? 'border-zinc-800 hover:border-rose-400/30'
                        : 'border-zinc-800 hover:border-emerald-400/30'
                    }`}
                  >
                    <div>
                      <div className="flex items-start justify-between mb-4 gap-2">
                        <div
                          className={`p-2.5 rounded-lg border ${
                            fuzzReport.isVulnerable
                              ? 'bg-rose-400/5 border-rose-400/15 text-rose-400'
                              : 'bg-emerald-400/5 border-emerald-400/15 text-emerald-400'
                          }`}
                        >
                          <BotMessageSquare className="w-5 h-5" />
                        </div>
                        <span
                          className={`text-[10px] font-mono tracking-wider px-2.5 py-1 rounded-md font-medium border text-right ${
                            fuzzReport.isVulnerable
                              ? 'bg-rose-400/10 text-rose-300 border-rose-400/20'
                              : 'bg-emerald-400/10 text-emerald-300 border-emerald-400/20'
                          }`}
                        >
                          {fuzzReport.isVulnerable ? t.fuzz.vulnerableBadge : t.fuzz.secureBadge}
                        </span>
                      </div>

                      <span
                        className={`text-[10px] font-mono uppercase tracking-widest block mb-1 ${
                          fuzzReport.isVulnerable ? 'text-rose-400' : 'text-emerald-400'
                        }`}
                      >
                        {t.fuzz.badge}
                      </span>
                      <h4 className="text-lg font-semibold text-zinc-100 mb-1">{t.fuzz.cardTitle}</h4>
                      <p className="text-xs text-zinc-400 leading-relaxed mb-4">{t.fuzz.cardDesc}</p>

                      <div className="rounded-lg p-3 mb-4 border bg-zinc-950/40 border-zinc-800">
                        <p
                          className={`text-sm font-semibold mb-1 ${
                            fuzzReport.isVulnerable ? 'text-rose-400' : 'text-emerald-400'
                          }`}
                        >
                          {fuzzReport.isVulnerable ? t.fuzz.vulnerableTitle : t.fuzz.secureTitle}
                        </p>
                        <p className="text-xs text-zinc-400 leading-relaxed">
                          {fuzzReport.isVulnerable ? t.fuzz.vulnerableDesc : t.fuzz.secureDesc}
                        </p>
                      </div>

                      {fuzzReport.isVulnerable && fuzzReport.successfulPayload && (
                        <div className="bg-zinc-950/60 border border-zinc-800 rounded-lg p-3 font-mono text-xs text-zinc-300 mb-4">
                          <div className="flex items-center justify-between text-zinc-500 mb-1.5 text-[11px] gap-2">
                            <span className="truncate">
                              {t.fuzz.payloadLabel}{' '}
                              <strong className="text-zinc-300 font-medium">{fuzzReport.successfulPayloadLabel}</strong>
                              {fuzzReport.successfulFormat ? (
                                <span className="text-zinc-500"> · {fuzzReport.successfulFormat}</span>
                              ) : null}
                            </span>
                            <button
                              type="button"
                              onClick={() => handleCopySnippet('fuzz-payload', fuzzReport.successfulPayload ?? '')}
                              className="text-zinc-500 hover:text-zinc-200 transition-colors cursor-pointer shrink-0"
                              title="Copy"
                            >
                              {copiedId === 'fuzz-payload' ? (
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          </div>
                          <p className="text-rose-400 break-words select-all">
                            &quot;{fuzzReport.successfulPayload}&quot;
                          </p>
                        </div>
                      )}

                      <div className="space-y-1.5 text-[11px] font-mono text-zinc-500">
                        <p className="break-all">
                          <span className="text-zinc-400">{t.fuzz.endpointLabel}</span>{' '}
                          {fuzzReport.endpointUrl}
                        </p>
                        <p>
                          <span className="text-zinc-400">{t.fuzz.testedLabel}</span>{' '}
                          {fuzzReport.payloadsTested}
                          {fuzzReport.totalCombinations ? `/${fuzzReport.totalCombinations}` : ''}
                          {' · '}
                          <span className="text-zinc-400">{t.fuzz.latencyLabel}</span>{' '}
                          {fuzzReport.durationMs}ms
                        </p>
                        {fuzzReport.isVulnerable && fuzzReport.results.find((r) => r.bypassed) && (
                          <p className="break-all">
                            <span className="text-zinc-400">{t.fuzz.responseLabel}</span>{' '}
                            <span className="text-rose-400/90">
                              {fuzzReport.results.find((r) => r.bypassed)?.responseSnippet}
                            </span>
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="mt-4 text-xs text-zinc-400 bg-zinc-950/40 p-3.5 rounded-lg border border-zinc-800">
                      <div className="flex items-center gap-1.5 font-medium text-zinc-200 mb-1">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                        <span>{t.report.mitigationHeader}</span>
                      </div>
                      <p className="leading-relaxed">
                        {fuzzReport.isVulnerable ? t.fuzz.mitigationVulnerable : t.fuzz.mitigationSecure}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Acciones del reporte */}
            <div className="flex items-center justify-between gap-4 pt-2">
              <span className="text-[11px] text-zinc-600 font-mono">
                {fuzzReport
                  ? new Date(fuzzReport.timestamp).toLocaleString(lang === 'es' ? 'es-ES' : 'en-US')
                  : report
                    ? new Date(report.scanTimestamp).toLocaleString(lang === 'es' ? 'es-ES' : 'en-US')
                    : ''}
              </span>
              <button
                type="button"
                onClick={() => void runScan()}
                disabled={!canScan}
                className="inline-flex items-center gap-2 px-4 py-2 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 disabled:opacity-50 disabled:cursor-not-allowed text-xs font-medium text-zinc-300 rounded-lg transition-colors cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5 text-emerald-400" />
                {t.report.reScan}
              </button>
            </div>
          </div>
        )}

        {/* Sección de Características / Propuesta de Valor */}
        <section className="w-full max-w-4xl mt-24 border-t border-zinc-800 pt-16">
          <div className="text-center mb-12">
            <h2 className="text-2xl sm:text-3xl font-semibold text-zinc-100 mb-3">
              {t.featuresSection.heading}
            </h2>
            <p className="text-zinc-500 text-sm max-w-xl mx-auto">
              {t.featuresSection.subheading}
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            <div className="p-5 rounded-xl bg-zinc-900/40 border border-zinc-800 hover:border-zinc-700 transition-colors">
              <div className="w-10 h-10 rounded-lg bg-emerald-400/5 border border-emerald-400/15 text-emerald-400 flex items-center justify-center mb-4">
                <KeyRound className="w-5 h-5" />
              </div>
              <h3 className="font-medium text-zinc-100 text-base mb-2">{t.featuresSection.f1_title}</h3>
              <p className="text-xs text-zinc-400 leading-relaxed">{t.featuresSection.f1_desc}</p>
            </div>

            <div className="p-5 rounded-xl bg-zinc-900/40 border border-zinc-800 hover:border-zinc-700 transition-colors">
              <div className="w-10 h-10 rounded-lg bg-zinc-800/60 border border-zinc-700 text-zinc-300 flex items-center justify-center mb-4">
                <BotMessageSquare className="w-5 h-5" />
              </div>
              <h3 className="font-medium text-zinc-100 text-base mb-2">{t.featuresSection.f2_title}</h3>
              <p className="text-xs text-zinc-400 leading-relaxed">{t.featuresSection.f2_desc}</p>
            </div>

            <div className="p-5 rounded-xl bg-zinc-900/40 border border-zinc-800 hover:border-zinc-700 transition-colors">
              <div className="w-10 h-10 rounded-lg bg-emerald-400/5 border border-emerald-400/15 text-emerald-400 flex items-center justify-center mb-4">
                <Layers className="w-5 h-5" />
              </div>
              <h3 className="font-medium text-zinc-100 text-base mb-2">{t.featuresSection.f3_title}</h3>
              <p className="text-xs text-zinc-400 leading-relaxed">{t.featuresSection.f3_desc}</p>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="relative z-10 border-t border-zinc-800 bg-[#141414] py-8 text-xs text-zinc-500 font-mono">
        <div className="max-w-5xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <p>{t.footer.copyright}</p>
          <div className="flex items-center gap-2 text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>{t.footer.status}</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
