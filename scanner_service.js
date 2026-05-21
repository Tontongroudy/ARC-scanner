const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const express = require('express');
const util = require('util');
const { exec } = require('child_process');
const execPromise = util.promisify(exec);
const axios = require('axios');
const OpenAI = require("openai");

const app = express();

app.use(express.json());
const SCANNER_API_KEY = process.env.SCANNER_API_KEY;
// Configuration des chemins des outils
const NMAP_CMD = 'nmap';
const NUCLEI_CMD = '"C:\\Program Files\\nuclei_3.8.0_windows_amd64\\nuclei.exe"';

// Vérification de la clé API OpenAI au démarrage
if (process.env.OPENAI_API_KEY) {
    console.log("✅ Clé API OpenAI chargée avec succès.");
} else {
    console.error("❌ ERREUR : Clé API OpenAI introuvable. Vérifiez le fichier .env à la racine.");
}

app.post('/run-scan', async (req, res) => {

    const apiKey = req.headers['x-scanner-api-key'];

    if (!apiKey || apiKey !== SCANNER_API_KEY) {

        return res.status(403).json({
            error: 'Accès interdit'
        });
    }    const { ticketId, targetIp, callbackUrl } = req.body;

    res.send({ status: 'started' });

    let scanSuccess = true;

    try {
        await sendWebhook(callbackUrl, {
            ticketId,
            type: 'status_update',
            status: 'prise en charge'
        });

        await sendWebhook(callbackUrl, {
            ticketId,
            type: 'status_message',
            content: `Démarrage du scan pour la cible : ${targetIp}.`
        });

        // Validation IP / domaine
        const ipRegex =
            /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/;

        if (!ipRegex.test(targetIp)) {
            throw new Error("Format d'IP ou de domaine invalide.");
        }

        // Début Nmap
        await sendWebhook(callbackUrl, {
            ticketId,
            type: 'status_update',
            status: 'en cours d’analyse'
        });

        await sendWebhook(callbackUrl, {
            ticketId,
            type: 'status_message',
            content: `Scan Nmap en cours pour ${targetIp}...`
        });

        let nmapOut = '';
        let nmapErr = '';

        try {
            const { stdout, stderr } = await execPromise(
                `${NMAP_CMD} -sV -T4 --top-ports 100 --script vulners --max-retries 1 --host-timeout 5m ${targetIp}`
            );

            nmapOut = stdout;
            nmapErr = stderr;

        } catch (nmapExecError) {

            nmapOut = `Erreur lors de l'exécution de Nmap: ${nmapExecError.message}.`;
            nmapErr = nmapExecError.stderr || nmapExecError.stdout || '';

            scanSuccess = false;

            await sendWebhook(callbackUrl, {
                ticketId,
                type: 'status_message',
                content: `Nmap a échoué: ${nmapExecError.message}`
            });
        }

        // Début Nuclei
        await sendWebhook(callbackUrl, {
            ticketId,
            type: 'status_message',
            content: 'Nmap terminé. Lancement de Nuclei...'
        });

        let nucleiOut = '';

        try {

            const { stdout } = await execPromise(
                `${NUCLEI_CMD} -u ${targetIp} -silent -no-color -severity critical,high,medium -timeout 5`
            );

            nucleiOut = stdout;

        } catch (nucleiExecError) {

            nucleiOut = `Erreur lors de l'exécution de Nuclei: ${nucleiExecError.message}`;

            scanSuccess = false;

            await sendWebhook(callbackUrl, {
                ticketId,
                type: 'status_message',
                content: `Nuclei a échoué: ${nucleiExecError.message}`
            });
        }

        // Début IA
        await sendWebhook(callbackUrl, {
            ticketId,
            type: 'status_message',
            content: 'Scans terminés. Analyse IA en cours...'
        });

        const aiAnalysis = await callAIProvider(
            ticketId,
            targetIp,
            nmapOut,
            nucleiOut,
            callbackUrl
        );

        // Rapport final
        let finalReport = `Rapport de Scan pour ${targetIp}\n\n`;

        finalReport +=
            "--- DIAGNOSTIC IA ---\n" +
            aiAnalysis +
            "\n\n";

        finalReport +=
            "--- RÉSULTATS NMAP ---\n" +
            nmapOut +
            (nmapErr ? `\nStderr: ${nmapErr}` : '') +
            "\n\n";

        finalReport +=
            "--- RÉSULTATS NUCLEI ---\n" +
            (nucleiOut || "Aucune vulnérabilité critique trouvée.") +
            "\n\n";

        await sendWebhook(callbackUrl, {
            ticketId,
            type: 'file_content',
            content: finalReport
        });

        await sendWebhook(callbackUrl, {
            ticketId,
            type: 'file_available'
        });

    } catch (error) {

        scanSuccess = false;

        await sendWebhook(callbackUrl, {
            ticketId,
            type: 'log',
            content: "Erreur lors du scan: " + error.message
        });

    } finally {

        await sendWebhook(callbackUrl, {
            ticketId,
            type: 'status_update',
            status: scanSuccess ? 'ouvert' : 'erreur'
        });
    }
});

async function sendWebhook(url, data) {
    try {
        await axios.post(url, data, {
            headers: { 'x-scanner-api-key': process.env.SCANNER_API_KEY }
        });
    } catch (e) {
        console.error("Webhook failed:", e.message);
    }
}

async function callAIProvider(ticketId, targetIp, nmap, nuclei, callbackUrl) {

    const AI_API_KEY = process.env.OPENAI_API_KEY;

    if (!AI_API_KEY) {

        console.warn("ATTENTION: Clé API OpenAI non configurée.");

        // Envoyer un message de statut au serveur principal
        await sendWebhook(callbackUrl, {
            ticketId: ticketId,
            type: 'status_message',
            content: "ATTENTION: Clé API OpenAI non configurée. L'analyse IA sera simulée."
        });
        return `[IA - SIMULÉE]
Analyse OpenAI pour ${targetIp}

- Sévérité: Moyenne
- Explication: Configurez votre clé API OpenAI.
- Recommandation: Vérifiez les résultats manuellement.`;
    }

    const openai = new OpenAI({
        apiKey: AI_API_KEY
    });

    const prompt = `
Analyse les résultats de scan suivants pour la cible ${targetIp}.

Résultat Nmap:
${nmap}

Résultat Nuclei:
${nuclei}

Identifie :
- les vulnérabilités
- leur sévérité
- une explication
- des recommandations
`;

    try {

        const response = await openai.chat.completions.create({
            model: "gpt-4o",
            messages: [
                {
                    role: "user",
                    content: prompt
                }
            ]
        });

        return response.choices[0].message.content;

    } catch (error) {

        console.error("Erreur API OpenAI:", error.message);

        return `Impossible d'obtenir une analyse IA : ${error.message}`;
    }
}

app.listen(4000, '127.0.0.1', () => {
    console.log('Scanner Service running on port 4000');
    console.log('Webhook cible : http://127.0.0.1:3000/api/scan/webhook (port HTTP interne)');
});