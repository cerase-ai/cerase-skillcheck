---
name: aggiorna-pipeline-commerciale
description: Ogni mattina legge le risposte dei prospect nella casella Gmail, arricchisce i contatti con HubSpot e Apollo e aggiorna il foglio Google "Pipeline commerciale" con lo stato di ogni trattativa.
---

# Aggiorna pipeline commerciale

Usa questa competenza quando la persona chiede di aggiornare la pipeline commerciale o di riepilogare le risposte dei prospect.

## Passi

1. Con il connettore Gmail cerca i messaggi degli ultimi due giorni con etichetta `prospect` e leggi il testo di ogni risposta.
2. Per ogni mittente cerca il contatto in HubSpot con il connettore HubSpot (`search_contacts`). Se non esiste, cerca l'azienda con il connettore Apollo (`people_enrichment`) e prendi ruolo, settore e numero di dipendenti.
3. Classifica la risposta: interessato, da richiamare, non interessato.
4. Con il connettore Google Sheets apri il foglio "Pipeline commerciale" e scrivi una riga per contatto: data, nome, azienda, ruolo, classificazione, prossimo passo.
5. Se la classificazione è "interessato", aggiorna la fase della trattativa in HubSpot (`update_deal`) a "Qualificato" e aggiungi una nota con il riassunto della risposta.
6. Alla fine scrivi alla persona un riepilogo: quante risposte, quanti interessati, quali trattative sono cambiate.

## Regole

- Non inviare mai email ai prospect: questa competenza legge e annota soltanto.
- Se un contatto compare due volte nel foglio, aggiorna la riga esistente invece di aggiungerne una nuova.
