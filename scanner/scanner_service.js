const path = require('path');
// On force la recherche du .env un dossier plus haut (à la racine)
require('dotenv').config({ path: path.resolve(__dirname, '../.env') }); 
const express = require('express');
const util = require('util');
const { exec } = require('child_process');
const execPromise = util.promisify(exec);
const axios = require('axios'); // Import axios for AI API calls
const OpenAI = require("openai");

const app = express();
app.use(express.json());
const NMAP_CMD = 'nmap';
const NUCLEI_CMD = '"C:\\\\Program Files\\\\nuclei_3.8.0_windows_amd64\\\\nuclei.exe"';

app.post('/run-scan', async (req, res) => {
    const { ticketId, targetIp, callbackUrl } = req.body;
    res.send({ status: 'launched' }); // Réponse immédiate

    let scanSuccess = true; // Flag pour suivre le succès global du scan

    try {
        await sendWebhook(callbackUrl, { ticketId, type: 'status_update', status: 'prise en charge' });
        await sendWebhook(callbackUrl, { ticketId, type: 'status_message', content: `Démarrage du scan pour la cible : ${targetIp}. (Le scan est lancé sur l'adresse IP de votre appareil actuel).` });
        // 1. Validation de l'IP (Sécurité)
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/;
        if (!ipRegex.test(targetIp)) {
            throw new Error("Format d'IP ou de domaine invalide.");
        }

        // 2. Notification au serveur principal (début Nmap)
        await sendWebhook(callbackUrl, { ticketId, type: 'status_update', status: "en cours d'analyse" });
        await sendWebhook(callbackUrl, { ticketId, type: 'status_message', content: `Lancement de l'analyse réseau sur ${targetIp}.` });
        
        // 3. Nmap - Optimisé : T4 (vitesse), top-ports 100, timeout 5m
        let nmapOut = '';
        let nmapErr = '';
        try {
            const { stdout, stderr } = await execPromise(`${NMAP_CMD} -sV -T4 --top-ports 100 --script vulners --max-retries 1 --host-timeout 5m ${targetIp}`);
            nmapOut = stdout || 'Aucun résultat Nmap.';
            nmapErr = stderr || '';
        } catch (nmapExecError) {
            nmapOut = `Erreur lors de l'exécution de Nmap: ${nmapExecError.message}.`;
            nmapErr = nmapExecError.stderr || nmapExecError.stdout || ''; // Capture stderr/stdout from exec error
            scanSuccess = false;
            await sendWebhook(callbackUrl, { ticketId, type: 'status_message', content: `Nmap a échoué: ${nmapExecError.message}. Vérifiez l'installation de Nmap sur ce serveur.` });
        }
        
        // Notification au serveur principal (fin Nmap, début Nuclei)
        await sendWebhook(callbackUrl, { ticketId, type: 'status_update', status: "en cours d'analyse" });
        await sendWebhook(callbackUrl, { ticketId, type: 'status_message', content: "Scan de vulnérabilités applicatives en cours." });

        // 4. Nuclei - Optimisé : timeout de 5s par requête
        await sendWebhook(callbackUrl, { ticketId, type: 'log', content: "Recherche de failles web (Nuclei)." });
        let nucleiOut = '';
        try {
            const { stdout } = await execPromise(`${NUCLEI_CMD} -u ${targetIp} -silent -no-color -timeout 5`);
            nucleiOut = stdout || "Aucune vulnérabilité trouvée.";
        } catch (nucleiExecError) {
            nucleiOut = `Erreur lors de l'exécution de Nuclei: ${nucleiExecError.message}`;
            scanSuccess = false;
            await sendWebhook(callbackUrl, { ticketId, type: 'status_message', content: `Nuclei a échoué: ${nucleiExecError.message}. Vérifiez l'installation de Nuclei sur ce serveur.` });
        }
        
        // Notification au serveur principal (fin Nuclei, début IA)
        await sendWebhook(callbackUrl, { ticketId, type: 'status_update', status: "en cours d'analyse" });
        await sendWebhook(callbackUrl, { ticketId, type: 'status_message', content: "Génération du diagnostic intelligent." });

        // 5. IA (Appel API LLM)
        const aiAnalysis = await callAIProvider(targetIp, nmapOut, nucleiOut);

        // 6. Construction du rapport final (Ordre: IA -> Nmap -> Nuclei)
        let finalReport = `Rapport de Scan pour ${targetIp}\n\n`;
        finalReport += "--- DIAGNOSTIC IA ARC ---\n" + aiAnalysis + "\n\n";
        finalReport += "--- RÉSULTATS NMAP (NON TOUCHÉ PAR L'IA) ---\n" + nmapOut + (nmapErr ? `\nStderr: ${nmapErr}` : '') + "\n\n";
        finalReport += "--- RÉSULTATS NUCLEI (NON TOUCHÉ PAR L'IA) ---\n" + (nucleiOut || "Aucune vulnérabilité critique trouvée par Nuclei.") + "\n\n";

        await sendWebhook(callbackUrl, { ticketId, type: 'status_update', status: "en cours d'analyse" });
        await sendWebhook(callbackUrl, { ticketId, type: 'status_message', content: "Diagnostic IA terminé. Génération du rapport..." });

        // 7. Envoi final des données au serveur principal
        await sendWebhook(callbackUrl, { ticketId, type: 'file_content', content: finalReport });
        await sendWebhook(callbackUrl, { ticketId, type: 'file_available' }); // Indique que le fichier est prêt

    } catch (error) {
        scanSuccess = false;
        await sendWebhook(callbackUrl, { ticketId, type: 'log', content: "Erreur lors du scan: " + error.message });
    } finally {
        // Toujours envoyer une mise à jour de statut finale
        await sendWebhook(callbackUrl, { ticketId, type: 'status_update', status: scanSuccess ? 'ouvert' : 'erreur' });
    }
});

async function sendWebhook(url, data) {
    try {
        await axios.post(url, data); // Utilisation d'axios pour les webhooks
    } catch (e) { console.error("Webhook failed:", e.message); }
}

async function callAIProvider(targetIp, nmap, nuclei) {
    const AI_API_KEY = process.env.OPENAI_API_KEY;

    if (!AI_API_KEY) {
        console.warn("ATTENTION: Clé API OpenAI non configurée. L'analyse IA sera simulée. (Utilisez un fichier .env)");
        return `[IA - SIMULÉE] Analyse OpenAI pour ${targetIp}:\n` +
               `- Sévérité: Information\n` +
               `- Explication: Configurez votre clé API OpenAI pour une analyse réelle.\n` +
               `- Recommandation: Vérifiez les résultats Nmap/Nuclei manuellement.`;
    }

    const openai = new OpenAI({ apiKey: AI_API_KEY });

    const prompt = `Analyse les résultats de scan suivants. Identifie les vulnérabilités, leur sévérité (Faible, Moyenne, Élevée, Critique), et fournis une explication détaillée ainsi que des recommandations de correction.

Résultat Nmap:
${nmap}

Résultat Nuclei:
${nuclei}

Structure ta réponse comme suit:
Sévérité Globale: [Sévérité la plus élevée détectée]
Vulnérabilités détectées:
- [Nom de la vulnérabilité 1] (Sévérité: [Sévérité])
  Explication: [Détails de la vulnérabilité]
  Recommandation: [Actions correctives]
- [Nom de la vulnérabilité 2] (Sévérité: [Sévérité])
  Explication: [Détails de la vulnérabilité]
  Recommandation: [Actions correctives]
...
Si aucune vulnérabilité majeure n'est trouvée, indique-le.`;

    try {
        const response = await openai.chat.completions.create({
            model: "gpt-4o",
            messages: [{ role: "user", content: prompt }],
        });
        const aiText = response.choices[0].message.content;
        
        console.log("Réponse de l'IA :", aiText);
        return aiText;
    } catch (error) {
        console.error("Erreur lors de l'appel à l'API OpenAI:", error.message);
        return `Impossible d'obtenir une analyse de l'IA. Erreur: ${error.message}`;
    }
}

app.listen(4000, '127.0.0.1', () => console.log('Scanner Service running on port 4000 (local only)'));