# 🛡️ VibeSec | Auditor de Seguridad para Microapps con IA

VibeSec es un microSaaS de ciberseguridad diseñado específicamente para el ecosistema *vibecoding*. Escanea repositorios en busca de secretos expuestos y realiza pruebas de estrés (fuzzing) contra ataques de inyección de prompts en endpoints de inteligencia artificial.

![VibeSec UI](https://via.placeholder.com/800x400.png?text=VibeSec+Soft+Terminal+Aesthetic)

## ✨ Características Principales

- **Cazador de Secretos:** Analiza archivos críticos (`.env`, `next.config.js`) en repositorios de GitHub buscando claves API expuestas (OpenAI, Anthropic, Supabase, etc.).
- **Fuzzer de Inyección de Prompts:** Ataca endpoints de IA personalizados con múltiples payloads maliciosos para verificar si el modelo obedece instrucciones del atacante por encima del *system prompt*.
- **Interfaz "Soft Terminal":** Diseño minimalista, oscuro y centrado en la experiencia del desarrollador.

## 🚀 Cómo probar VibeSec en local

Para ejecutar este proyecto en tu propio entorno, necesitarás configurar tus propias claves de API.

1. **Clona el repositorio:**
   ```bash
   git clone [https://github.com/TU_USUARIO/vibesec.git](https://github.com/TU_USUARIO/vibesec.git)
   cd vibesec
Instala las dependencias:

Bash
npm install
Configura el entorno:
Copia el archivo de ejemplo y añade tus propias credenciales de Groq/GCP.

Bash
cp .env.example .env.local
Inicia el servidor de desarrollo:

Bash
npm run dev
Abre http://localhost:3000 en tu navegador para ver la aplicación.

🛠️ Stack Tecnológico
Framework: Next.js (App Router)

Estilos: Tailwind CSS

Lenguaje: TypeScript

⚠️ Aviso Legal
VibeSec es una herramienta de auditoría defensiva. Utiliza el fuzzer únicamente en endpoints y repositorios sobre los que tengas autorización explícita.
