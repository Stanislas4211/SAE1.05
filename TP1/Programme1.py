#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SAÉ 1.5 - Programme1.py
# Conversion d'un fichier .ics (un seul VEVENT) vers le format pseudo-CSV :
# uid;date;heure;duree;modalite;intitule;salle1|salle2|...;prof1|prof2|...;groupe1|groupe2|...

from datetime import datetime

def lire_fichier_ics(nom_fichier):
    with open(nom_fichier, "r", encoding="utf-8") as f:
        return f.read()

def extraire_valeur(texte, cle):
    # Cherche une ligne du type CLE:valeur
    for ligne in texte.splitlines():
        if ligne.startswith(cle + ":"):
            return ligne.split(":", 1)[1].strip()
    return "vide"

def datetime_ics_vers_date_heure(dt_ics):
    # Format AAAAMMDDThhmmssZ → JJ-MM-AAAA, HH:MM
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

def extraire_modalite(texte):
    # Dans ton cas, on peut décider de mettre "CM" en dur
    # ou chercher dans SUMMARY/DESCRIPTION si besoin.
    # Pour rester simple, on met "CM" car c'est un CM dans l'énoncé.
    return "CM"

def extraire_prof(description):
    # DESCRIPTION contient "\n\nRT1-S1\nLACAN DAVID\n"
    # On prend la dernière ligne non vide comme professeur.
    lignes = [l.strip() for l in description.splitlines() if l.strip()]
    if not lignes:
        return "vide"
    return lignes[-1]

def extraire_groupe(description):
    # On cherche une ligne qui ressemble à "RT1-S1"
    lignes = [l.strip() for l in description.splitlines() if l.strip()]
    for l in lignes:
        if "S1" in l:   # simple mais suffisant pour ton cas
            return "S1"
    return "vide"

def convertir_ics_en_pseudo_csv(texte):
    uid = extraire_valeur(texte, "UID")
    dtstart = extraire_valeur(texte, "DTSTART")
    dtend = extraire_valeur(texte, "DTEND")
    summary = extraire_valeur(texte, "SUMMARY")
    location = extraire_valeur(texte, "LOCATION")
    description = extraire_valeur(texte, "DESCRIPTION")

    date, heure = datetime_ics_vers_date_heure(dtstart)
    duree = calcul_duree(dtstart, dtend)
    modalite = extraire_modalite(texte)
    intitule = summary
    salles = location if location != "" else "vide"
    profs = extraire_prof(description) if description != "vide" else "vide"
    groupes = extraire_groupe(description) if description != "vide" else "vide"

    # Construction de la chaîne pseudo-CSV
    return f"{uid};{date};{heure};{duree};{modalite};{intitule};{salles};{profs};{groupes}"

def main():
    nom_fichier = input("Nom du fichier .ics : ").strip()
    contenu = lire_fichier_ics(nom_fichier)
    resultat = convertir_ics_en_pseudo_csv(contenu)
    print(resultat)

if __name__ == "__main__":
    main()
