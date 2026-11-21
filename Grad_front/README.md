# Sentinel SOC console

React dashboard for the Tracee → SignalR security event pipeline.

## Run locally

1. Start the .NET backend in `C:\Users\osama\Projects\Test`:

   ```powershell
   dotnet run
   ```

2. In this directory, install and start the console:

   ```powershell
   npm install
   npm run dev
   ```

3. Open `http://localhost:5173`. The Vite server proxies `/logs` to the backend at `http://localhost:5086`, so SignalR works without a browser CORS issue.

4. Start the collector from `C:\Users\osama\Projects\SOC\Run\Run` once Tracee is producing events.

## Deployment

Run `npm run build` to create `dist/`. Set `VITE_BACKEND_URL` to the HTTPS public origin of the .NET backend at build time. On the backend, set `CLIENT_ORIGINS` to the exact deployed dashboard origin (comma-separated when more than one is needed).

## Live-data contract

The console subscribes to the `newLog` SignalR event on `/logs`, mapping the backend's `Log` object directly into a triage record. It also exposes process metadata, MITRE-oriented categorisation, severity and workflow statuses in the incident drawer.

The AI project currently has no published HTTP/SSE endpoint and its report node is marked unimplemented, so the UI deliberately labels the AI report as staged rather than fabricating an integration. Once that endpoint exists, its output can be attached to the existing incident detail drawer.
