# Programme1.py
import tkinter as tk
from tkinter import filedialog

def choisir_fichier_ics():
    """Ouvre une boîte de dialogue pour sélectionner un fichier .ics et renvoie son chemin."""
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier ICS",
        filetypes=[("Fichiers ICS", "*.ics")]
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
    """
    Construit une chaîne de type pseudo-CSV à partir du contenu ICS.
    Exemple de sortie :
    DTSTAMP;DTSTART;DTEND;SUMMARY;LOCATION;DESCRIPTION
    20251210T214451Z;20251205T090000Z;20251205T110000Z;SAE1.05;G_011_AMPHI;\\n\\nRT1-S1\\nLACAN DAVID\\n
    """
    lignes = contenu.splitlines()

    dtstamp = extraire_champ(lignes, "DTSTAMP")
    dtstart = extraire_champ(lignes, "DTSTART")   # début de l'événement [web:1]
    dtend   = extraire_champ(lignes, "DTEND")     # fin de l'événement [web:1]
    summary = extraire_champ(lignes, "SUMMARY")   # titre de l'événement [web:1]
    location = extraire_champ(lignes, "LOCATION") # lieu de l'événement [web:1]
    description = extraire_champ(lignes, "DESCRIPTION")  # description [web:5]

    # ligne d'entête + ligne de données
    entete = "DTSTAMP;DTSTART;DTEND;SUMMARY;LOCATION;DESCRIPTION"
    donnees = f"{dtstamp};{dtstart};{dtend};{summary};{location};{description}"
    pseudo_csv = entete + "\n" + donnees

    return pseudo_csv

def afficher_resultat(fenetre, texte_resultat, pseudo_csv):
    """Affiche le pseudo-CSV dans la zone de texte."""
    texte_resultat.config(state="normal")
    texte_resultat.delete("1.0", tk.END)
    texte_resultat.insert(tk.END, pseudo_csv)
    texte_resultat.config(state="disabled")

def traiter_fichier(texte_resultat):
    """Gère tout le traitement : choix du fichier, lecture, extraction, affichage."""
    chemin = choisir_fichier_ics()
    if not chemin:
        return
    contenu = lire_fichier_ics(chemin)
    pseudo_csv = construire_pseudo_csv(contenu)
    afficher_resultat(fenetre, texte_resultat, pseudo_csv)

def main():
    global fenetre
    fenetre = tk.Tk()
    fenetre.title("Programme1 - ICS vers pseudo-CSV")
    fenetre.geometry("700x300")

    # Bouton pour choisir et traiter le fichier
    btn_choisir = tk.Button(
        fenetre,
        text="Choisir un fichier ICS",
        command=lambda: traiter_fichier(texte_resultat)
    )
    btn_choisir.pack(pady=10)

    # Zone d'affichage du pseudo-CSV
    texte_resultat = tk.Text(fenetre, height=10, width=80)
    texte_resultat.pack(padx=10, pady=10)
    texte_resultat.config(state="disabled")

    # Bouton quitter
    btn_quitter = tk.Button(fenetre, text="Quitter", command=fenetre.quit)
    btn_quitter.pack(pady=10)

    fenetre.mainloop()

if __name__ == "__main__":
    main()
