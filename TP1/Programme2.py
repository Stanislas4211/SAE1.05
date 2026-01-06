#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime

def lire_fichier_ics(nom_fichier):
    with open(nom_fichier, "r", encoding="utf-8") as f:
        return f.read()

def extraire_valeur_bloc(bloc, cle):
    for ligne in bloc.splitlines():
        if ligne.startswith(cle + ":"):
            return ligne.split(":", 1)[1].strip()
    return "vide"

def datetime_ics_vers_date_heure(dt_ics):
    if dt_ics == "vide":
        return "vide", "vide"
    dt_ics = dt_ics.rstrip("Z")
    dt = datetime.strptime(dt_ics, "%Y%m%dT%H%M%S")
    date = dt.strftime("%d-%m-%Y")
    heure = dt.strftime("%H:%M")
    return date, heure

def calcul_duree(dtstart, dtend):
    if dtstart == "vide" or dtend == "vide":
        return "vide"
    dtstart = dtstart.rstrip("Z")
    dtend = dtend.rstrip("Z")
    d1 = datetime.strptime(dtstart, "%Y%m%dT%H%M%S")
    d2 = datetime.strptime(dtend, "%Y%m%dT%H%M%S")
    delta = d2 - d1
    total_minutes = delta.seconds // 60
    h = total_minutes // 60
    m = total_minutes % 60
    return f"{h:02d}:{m:02d}"

def extraire_modalite(bloc):
    modalites = ["CM", "TD", "TP", "Proj", "DS"]
    for mod in modalites:
        if mod in bloc:
            return mod
    return "vide"

def extraire_prof(description):
    if description == "vide":
        return "vide"
    lignes = [l.strip() for l in description.splitlines() if l.strip()]
    if not lignes:
        return "vide"
    return lignes[-1]

def extraire_groupe(description):
    if description == "vide":
        return "vide"
    mots = description.replace("\n", " ").split()
    for mot in mots:
        if len(mot) == 2 and mot[0].isalpha() and mot[1].isdigit():
            return mot
        if mot.startswith("S") and mot[1:].isdigit():
            return mot
    return "vide"

def convertir_bloc_en_pseudo_csv(bloc):
    uid = extraire_valeur_bloc(bloc, "UID")
    dtstart = extraire_valeur_bloc(bloc, "DTSTART")
    dtend = extraire_valeur_bloc(bloc, "DTEND")
    summary = extraire_valeur_bloc(bloc, "SUMMARY")
    location = extraire_valeur_bloc(bloc, "LOCATION")
    description = extraire_valeur_bloc(bloc, "DESCRIPTION")

    date, heure = datetime_ics_vers_date_heure(dtstart)
    duree = calcul_duree(dtstart, dtend)
    modalite = extraire_modalite(bloc)
    intitule = summary if summary != "vide" else "vide"
    salles = location if location not in ("vide", "") else "vide"
    profs = extraire_prof(description)
    groupes = extraire_groupe(description)

    return f"{uid};{date};{heure};{duree};{modalite};{intitule};{salles};{profs};{groupes}"

def extraire_blocs_evenements(contenu):
    lignes = contenu.splitlines()
    blocs = []
    courant = []
    dans_event = False

    for ligne in lignes:
        if ligne.startswith("BEGIN:VEVENT"):
            dans_event = True
            courant = [ligne]
        elif ligne.startswith("END:VEVENT"):
            courant.append(ligne)
            blocs.append("\n".join(courant))
            dans_event = False
            courant = []
        else:
            if dans_event:
                courant.append(ligne)

    return blocs

def main():
    nom_fichier = input("Nom du fichier .ics (calendrier complet) : ").strip()
    contenu = lire_fichier_ics(nom_fichier)
    blocs = extraire_blocs_evenements(contenu)

    lignes_csv = []
    for bloc in blocs:
        lignes_csv.append(convertir_bloc_en_pseudo_csv(bloc))

    # Écriture dans un fichier CSV (séparateur ';')
    nom_csv = "evenements.csv"
    with open(nom_csv, "w", encoding="utf-8") as f:
        # éventuellement une ligne d’en-tête :
        f.write("uid;date;heure;duree;modalite;intitule;salles;profs;groupes\n")
        for ligne in lignes_csv:
            f.write(ligne + "\n")

    print(f"Fichier CSV généré : {nom_csv}")

if __name__ == "__main__":
    main()
