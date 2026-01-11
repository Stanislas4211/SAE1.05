#!/usr/bin/env python3
# ics_vers_pseudo_csv_une_activite.py

import tkinter as tk
from tkinter import filedialog, messagebox
import os


def choisir_fichier_ics():
    """Ouvre une boîte de dialogue pour sélectionner un fichier .ics et renvoie son chemin."""
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier ICS (1 activité)",
        filetypes=[("Fichiers ICS", "*.ics"), ("Tous les fichiers", "*.*")]
    )
    return chemin_fichier


def lire_fichier_ics(chemin):
    """Lit tout le contenu du fichier ICS et le renvoie sous forme de chaîne."""
    with open(chemin, "r", encoding="utf-8") as f:
        return f.read()


def extraire_champ(lignes, nom_champ):
    """Recherche une ligne commençant par nom_champ et renvoie la partie après ':'."""
    for ligne in lignes:
        if ligne.startswith(nom_champ + ":"):
            return ligne.split(":", 1)[1].strip()
    return ""


def construire_pseudo_csv(contenu):
    """Construit une chaîne de type pseudo-CSV à partir du contenu ICS (une activité)."""
    lignes = contenu.splitlines()

    dtstamp       = extraire_champ(lignes, "DTSTAMP")
    dtstart       = extraire_champ(lignes, "DTSTART")
    dtend         = extraire_champ(lignes, "DTEND")
    summary       = extraire_champ(lignes, "SUMMARY")
    location      = extraire_champ(lignes, "LOCATION")
    description   = extraire_champ(lignes, "DESCRIPTION")
    uid           = extraire_champ(lignes, "UID")
    created       = extraire_champ(lignes, "CREATED")
    last_modified = extraire_champ(lignes, "LAST-MODIFIED")
    sequence      = extraire_champ(lignes, "SEQUENCE")

    entete = (
        "DTSTAMP;DTSTART;DTEND;SUMMARY;LOCATION;"
        "DESCRIPTION;UID;CREATED;LAST-MODIFIED;SEQUENCE"
    )
    donnees = (
        f"{dtstamp};{dtstart};{dtend};{summary};{location};"
        f"{description};{uid};{created};{last_modified};{sequence}"
    )

    pseudo_csv = entete + "\n" + donnees
    return pseudo_csv


def sauvegarder_pseudo_csv(chaine_pseudo_csv):
    """
    Enregistre la chaîne pseudo-CSV dans le fichier 'Pseudo-Code CSV.csv'
    dans le même répertoire que le programme (ici TP1).
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    chemin_fichier = os.path.join(base_dir, "Pseudo-Code CSV.csv")

    with open(chemin_fichier, "w", encoding="utf-8") as f:
        f.write(chaine_pseudo_csv)

    return chemin_fichier


def afficher_message_creation(texte_resultat, chemin_fichier):
    """Affiche un message indiquant où le fichier a été créé."""
    texte_resultat.config(state="normal")
    texte_resultat.delete("1.0", tk.END)
    texte_resultat.insert(
        tk.END,
        "Le fichier pseudo-CSV a été créé.\n\n"
        f"Chemin : {chemin_fichier}\n\n"
        "Vous pouvez l'ouvrir avec un tableur (Excel, LibreOffice, etc.)."
    )
    texte_resultat.config(state="disabled")


def traiter_fichier(texte_resultat):
    """Choix du fichier, génération du pseudo-CSV, sauvegarde et message de confirmation."""
    chemin = choisir_fichier_ics()
    if not chemin:
        return

    contenu = lire_fichier_ics(chemin)
    pseudo_csv = construire_pseudo_csv(contenu)

    chemin_fichier = sauvegarder_pseudo_csv(pseudo_csv)

    afficher_message_creation(texte_resultat, chemin_fichier)
    messagebox.showinfo(
        "Fichier créé",
        f"Le fichier pseudo-CSV a été généré dans :\n{chemin_fichier}"
    )


def main():
    global fenetre
    fenetre = tk.Tk()
    fenetre.title("ICS (1 activité) vers pseudo-CSV")
    fenetre.geometry("700x220")

    texte_resultat = tk.Text(fenetre, height=5, width=80)
    texte_resultat.pack(padx=10, pady=10)
    texte_resultat.config(state="disabled")

    btn_choisir = tk.Button(
        fenetre,
        text="Choisir un fichier ICS (une activité)",
        command=lambda: traiter_fichier(texte_resultat)
    )
    btn_choisir.pack(pady=10)

    btn_quitter = tk.Button(fenetre, text="Quitter", command=fenetre.quit)
    btn_quitter.pack(pady=5)

    fenetre.mainloop()


if __name__ == "__main__":
    main()
