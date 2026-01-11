#!/usr/bin/env python3
# ics_multi_activites_vers_pseudo_csv.py

import tkinter as tk
from tkinter import filedialog, messagebox
import os


# ========= Fonctions de base (inspirées de Programme1) =========

def choisir_fichier_ics():
    """Ouvre une boîte de dialogue pour sélectionner un fichier .ics et renvoie son chemin."""
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier ICS (plusieurs activités)",
        filetypes=[("Fichiers ICS", "*.ics"), ("Tous les fichiers", "*.*")]
    )
    return chemin_fichier


def lire_fichier_ics(chemin):
    """Lit tout le contenu du fichier ICS et le renvoie sous forme de chaîne."""
    with open(chemin, "r", encoding="utf-8") as f:
        return f.read()


def extraire_champs_multiples(lignes, nom_champ):
    """
    Récupère toutes les lignes 'NOM_CHAMP:...' et retourne 'val1|val2|...' ou 'vide'.
    Sert pour LOCATION (plusieurs salles possibles).
    """
    prefix = nom_champ + ":"
    valeurs = []
    for ligne in lignes:
        if ligne.startswith(prefix):
            valeur = ligne.split(":", 1)[1].strip()
            valeur = valeur.replace("\\n", " ").strip()
            if valeur:
                valeurs.append(valeur)

    if not valeurs:
        return "vide"
    if len(valeurs) == 1:
        return valeurs[0]
    return "|".join(valeurs)


def extraire_champ_simple(lignes, nom_champ):
    """Comme extraire_champ de ton Programme1, pour un champ unique."""
    prefix = nom_champ + ":"
    for ligne in lignes:
        if ligne.startswith(prefix):
            valeur = ligne.split(":", 1)[1].strip()
            return valeur
    return "vide"


def extraire_profs_et_groupes(lignes):
    """
    À partir des DESCRIPTION, sépare GROUPES et PROFS.
    Hypothèse :
      - les lignes qui commencent par 'RT1-' sont des groupes (RT1-TP_B2, RT1-S1, RT1-B, etc.)
      - les autres lignes non vides sont des profs (noms).
    Retourne (profs_str, groupes_str) avec '|' comme séparateur et 'vide' si rien.
    """
    prefix = "DESCRIPTION:"
    lignes_brutes = []

    for ligne in lignes:
        if ligne.startswith(prefix):
            texte = ligne.split(":", 1)[1]
            lignes_brutes.append(texte)

    if not lignes_brutes:
        return "vide", "vide"

    # On remet tous les morceaux ensemble, on remplace "\n" texte par de vrais sauts de ligne
    texte_complet = "\\n".join(lignes_brutes)
    texte_complet = texte_complet.replace("\\n", "\n")

    lignes_desc = [l.strip() for l in texte_complet.splitlines() if l.strip()]

    groupes = []
    profs = []

    for l in lignes_desc:
        if l.startswith("RT1-"):
            groupes.append(l)
        else:
            profs.append(l)

    def join_ou_vide(lst):
        if not lst:
            return "vide"
        return "|".join(lst)

    return join_ou_vide(profs), join_ou_vide(groupes)


# ========= Découpage en VEVENT =========

def extraire_evenements_vevent(contenu_complet):
    """Renvoie une liste de blocs texte, chacun correspondant à un VEVENT."""
    lignes = contenu_complet.splitlines()
    evenements = []
    bloc = []
    dans_vevent = False

    for ligne in lignes:
        if ligne.startswith("BEGIN:VEVENT"):
            dans_vevent = True
            bloc = [ligne]
        elif ligne.startswith("END:VEVENT"):
            bloc.append(ligne)
            dans_vevent = False
            evenements.append("\n".join(bloc))
            bloc = []
        elif dans_vevent:
            bloc.append(ligne)

    return evenements


# ========= Construction du pseudo-CSV pour un événement =========

def parse_datetime_ics(dt):
    """
    Convertit un datetime ICS AAAAMMDDThhmmssZ en (DATE, HEURE) = (JJ-MM-AAAA, HH:MM).
    """
    if dt == "vide":
        return "vide", "vide"
    dt = dt.split(";")[0]
    dt = dt.replace("Z", "")
    if len(dt) < 13:
        return "vide", "vide"
    date = dt[6:8] + "-" + dt[4:6] + "-" + dt[0:4]
    heure = dt[9:11] + ":" + dt[11:13]
    return date, heure


def calculer_duree(h_deb, h_fin):
    """Calcule la durée HH:MM à partir des heures 'HH:MM'."""
    if h_deb == "vide" or h_fin == "vide":
        return "vide"
    hd, md = int(h_deb[0:2]), int(h_deb[3:5])
    hf, mf = int(h_fin[0:2]), int(h_fin[3:5])
    minutes_deb = hd * 60 + md
    minutes_fin = hf * 60 + mf
    delta = minutes_fin - minutes_deb
    if delta < 0:
        return "vide"
    h = delta // 60
    m = delta % 60
    return f"{h:02d}:{m:02d}"


def construire_pseudo_csv_evenement(bloc_vevent):
    """
    Construit une chaîne pseudo-CSV pour un événement :
    UID;DATE;HEURE;DUREE;MODALITE;INTITULE;SALLES;PROFS;GROUPES
    """
    lignes = bloc_vevent.splitlines()

    uid         = extraire_champ_simple(lignes, "UID")
    dtstart_raw = extraire_champ_simple(lignes, "DTSTART")
    dtend_raw   = extraire_champ_simple(lignes, "DTEND")
    summary     = extraire_champ_simple(lignes, "SUMMARY")
    location    = extraire_champs_multiples(lignes, "LOCATION")   # SALLES
    profs, groupes = extraire_profs_et_groupes(lignes)            # PROFS / GROUPES

    date, heure_debut = parse_datetime_ics(dtstart_raw)
    date_fin, heure_fin = parse_datetime_ics(dtend_raw)
    duree = calculer_duree(heure_debut, heure_fin)

    # Modalité + intitulé à partir de SUMMARY
    modalite = "vide"
    intitule = summary

    for mod in ["CM", "TD", "TP", "Proj", "DS"]:
        if summary.startswith(mod + " "):
            modalite = mod
            intitule = summary[len(mod):].strip()
            break

    ligne = f"{uid};{date};{heure_debut};{duree};{modalite};{intitule};{location};{profs};{groupes}"
    return ligne


def construire_tableau_pseudo_csv(contenu_ics):
    """Renvoie une liste de chaînes pseudo-CSV (une par VEVENT)."""
    blocs = extraire_evenements_vevent(contenu_ics)
    tableau = []
    for bloc in blocs:
        ligne = construire_pseudo_csv_evenement(bloc)
        tableau.append(ligne)
    return tableau


# ========= Sauvegarde et interface =========

def sauvegarder_tableau(tableau, nom_fichier="Pseudo-Code CSV_Multi.csv"):
    """Sauvegarde le tableau dans un CSV (une ligne par événement)."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    chemin_fichier = os.path.join(base_dir, nom_fichier)

    with open(chemin_fichier, "w", encoding="utf-8") as f:
        # ENTETES EN MAJUSCULE
        f.write("UID;DATE;HEURE;DUREE;MODALITE;INTITULE;SALLES;PROFS;GROUPES\n")
        for ligne in tableau:
            f.write(ligne + "\n")

    return chemin_fichier


def afficher_message_creation(texte_resultat, chemin_fichier, nb_evt):
    texte_resultat.config(state="normal")
    texte_resultat.delete("1.0", tk.END)
    texte_resultat.insert(
        tk.END,
        f"Le fichier pseudo-CSV multiple a été créé.\n\n"
        f"Chemin : {chemin_fichier}\n"
        f"Nombre d'événements traités : {nb_evt}\n\n"
        "Ouvrez-le avec Excel en choisissant le séparateur ';'."
    )
    texte_resultat.config(state="disabled")


def traiter_fichier(texte_resultat):
    chemin = choisir_fichier_ics()
    if not chemin:
        return

    contenu = lire_fichier_ics(chemin)
    tableau_pseudo = construire_tableau_pseudo_csv(contenu)

    if not tableau_pseudo:
        messagebox.showwarning("Erreur", "Aucun événement VEVENT n'a été trouvé dans ce fichier.")
        return

    chemin_fichier = sauvegarder_tableau(tableau_pseudo)

    afficher_message_creation(texte_resultat, chemin_fichier, len(tableau_pseudo))
    messagebox.showinfo(
        "Fichier créé",
        f"Le fichier pseudo-CSV multiple a été généré dans :\n{chemin_fichier}"
    )


def main():
    global fenetre
    fenetre = tk.Tk()
    fenetre.title("ICS (multi-activités) vers pseudo-CSV")
    fenetre.geometry("750x260")

    texte_resultat = tk.Text(fenetre, height=7, width=90)
    texte_resultat.pack(padx=10, pady=10)
    texte_resultat.config(state="disabled")

    btn_choisir = tk.Button(
        fenetre,
        text="Choisir un fichier ICS (plusieurs activités)",
        command=lambda: traiter_fichier(texte_resultat)
    )
    btn_choisir.pack(pady=10)

    btn_quitter = tk.Button(fenetre, text="Quitter", command=fenetre.quit)
    btn_quitter.pack(pady=5)

    fenetre.mainloop()


if __name__ == "__main__":
    main()
