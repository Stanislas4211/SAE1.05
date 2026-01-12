import tkinter as tk
from tkinter import filedialog, messagebox
import re
import csv
import webbrowser
from collections import Counter, defaultdict
import os
import matplotlib.pyplot as plt

from rapport_html import generer_html


# ============================================================
# OUTILS GÉNÉRAUX (fichiers, temps, clés)
# ============================================================

# Retourne le chemin du répertoire de sortie (créé s'il n'existe pas)
def get_output_dir():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(base_dir, "Fichier renvoyé")
    os.makedirs(out_dir, exist_ok=True)
    return out_dir

# Ouvre une boîte de dialogue pour choisir le fichier texte réseau à analyser
def choisir_fichier_reseau():
    return filedialog.askopenfilename(
        title="Sélectionner un fichier texte réseau",
        filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")]
    )

# Lit toutes les lignes du fichier réseau et renvoie une liste de chaînes
def lire_fichier(chemin):
    with open(chemin, "r", encoding="utf-8") as f:
        return [l.rstrip("\n") for l in f]

# Convertit une heure "HH:MM:SS.xxx" en secondes depuis minuit
def parse_time(hhmmss):
    h, m, s = hhmmss.split(":")
    s = float(s)
    return int(h) * 3600 + int(m) * 60 + s

# Construit une clé (destination IP, port) pour un paquet
def cle_destination(e):
    return (e["dst_host"], str(e["dst_port"]))


# ============================================================
# PARSING DES LIGNES TCPDUMP -> TABLEAU D'ÉVÉNEMENTS
#   (En informatique, le parsing désigne le processus qui consiste à analyser une suite de symboles ou de données pour en dégager une structure et des éléments exploitables par un programme)
# ============================================================

# Expression régulière pour extraire les champs importants d'une ligne tcpdump
REG_IP = re.compile(
    r'^(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<src>[\w\.-]+)\.(?P<src_port>[\w\d]+)\s*>\s*'
    r'(?P<dst>[\w\.-]+)\.(?P<dst_port>[\w\d]+):\s*'
    r'Flags\s+\[(?P<flags>[^\]]*)\].*?'
    r'length\s+(?P<length>\d+)'
)

# Sépare un nom de type "machine.port" en (machine, port)
def split_host_port(nom):
    parts = nom.split(".")
    if len(parts) >= 2:
        host = ".".join(parts[:-1])
        port = parts[-1]
    else:
        host = nom
        port = "vide"
    return host, port

# Convertit une ligne brute tcpdump en dictionnaire structuré (ou None si non IP)
def ligne_vers_dict(ligne):
    m = REG_IP.match(ligne)
    if not m:
        return None
    d = m.groupdict()

    src_host, src_port2 = split_host_port(d["src"])
    dst_host, dst_port2 = split_host_port(d["dst"])

    return {
        "heure": d["time"],
        "src_host": src_host,
        "src_port": d.get("src_port") or src_port2,
        "dst_host": dst_host,
        "dst_port": d.get("dst_port") or dst_port2,
        "flags": d["flags"],
        "length": int(d["length"]),
    }

# Transforme toutes les lignes brutes en tableau de dictionnaires d'événements
def construire_tableau(lignes):
    table = []
    for l in lignes:
        evt = ligne_vers_dict(l)
        if evt is not None:
            table.append(evt)
    return table

# Écrit le tableau d'événements dans un CSV séparé par des points-virgules
def ecrire_csv(table, chemin_csv):
    if not table:
        return
    champs = ["heure", "src_host", "src_port", "dst_host", "dst_port", "flags", "length"]
    with open(chemin_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=champs, delimiter=";")
        w.writeheader()
        for e in table:
            w.writerow(e)

# Calcule le nombre total de paquets et le volume total en octets
def analyser_globale(table):
    return {
        "nb_total": len(table),
        "octets_total": sum(e["length"] for e in table),
    }


# ============================================================
# STATISTIQUES GÉNÉRALES POUR LA SYNTHÈSE
# ============================================================

# Renvoie le top N des IP sources les plus présentes
def stats_ip_sources(table, top_n=10):
    return Counter(e["src_host"] for e in table).most_common(top_n)

# Renvoie le top N des IP destinations les plus présentes
def stats_ip_destinations(table, top_n=10):
    return Counter(e["dst_host"] for e in table).most_common(top_n)

# Renvoie la liste des longueurs de paquets (en octets)
def stats_longueurs(table):
    return [e["length"] for e in table]

# Compte les paquets par protocole approximatif (DNS/SSH/HTTP/HTTPS/AUTRES)
def stats_protocoles(table):
    counts = Counter()
    for e in table:
        port = str(e["dst_port"])
        if port in ("53", "domain"):
            counts["DNS"] += 1
        elif port in ("22", "ssh"):
            counts["SSH"] += 1
        elif port in ("80", "http"):
            counts["HTTP"] += 1
        elif port in ("443", "https"):
            counts["HTTPS"] += 1
        else:
            counts["AUTRES"] += 1
    return counts


# ============================================================
# STATISTIQUES SSH
# ============================================================

# Filtre la table pour ne garder que les paquets SSH (port 22 ou service ssh)
def filtrer_ssh(table):
    ssh_pkts = []
    for e in table:
        if (str(e["src_port"]) == "22" or str(e["dst_port"]) == "22"
            or e["src_port"] == "ssh" or e["dst_port"] == "ssh"):
            ssh_pkts.append(e)
    return ssh_pkts

# Regroupe les paquets SSH par (client, serveur) et compte paquets / octets
def stats_ssh_sessions(table):
    sessions = defaultdict(lambda: {
        "pkts": 0,
        "bytes_total": 0,
        "bytes_client": 0,
        "bytes_server": 0,
    })
    ssh_pkts = filtrer_ssh(table)

    for e in ssh_pkts:
        key = (e["src_host"], e["dst_host"])
        s = sessions[key]
        s["pkts"] += 1
        s["bytes_total"] += e["length"]

        if str(e["src_port"]) == "22" or e["src_port"] == "ssh":
            s["bytes_server"] += e["length"]
        else:
            s["bytes_client"] += e["length"]

    return sessions

# Compte la fréquence de chaque flag TCP dans les paquets SSH
def stats_flags_ssh(table):
    ssh_pkts = filtrer_ssh(table)
    counts = Counter()
    for e in ssh_pkts:
        for ch in e["flags"]:
            if ch.isalpha():
                counts[ch] += 1
    return counts


# ============================================================
# STATISTIQUES SCAN / SYN
# ============================================================

# Indique si un paquet est un SYN "pur" (S mais pas A)
def est_syn(e):
    f = e["flags"]
    return "S" in f and "A" not in f

# Renvoie les intervalles temporels entre SYN successifs des sources les plus actives
def stats_intervalles_syn_par_source(table, top_n_sources=3):
    syn_par_src = defaultdict(list)
    for e in table:
        if est_syn(e):
            t = parse_time(e["heure"])
            syn_par_src[e["src_host"]].append(t)

    for src in syn_par_src:
        syn_par_src[src].sort()

    counts = [(src, len(ts)) for src, ts in syn_par_src.items()]
    counts.sort(key=lambda x: x[1], reverse=True)
    top_sources = [src for src, _ in counts[:top_n_sources]]

    intervalles = []
    for src in top_sources:
        ts = syn_par_src[src]
        for i in range(1, len(ts)):
            intervalles.append(ts[i] - ts[i - 1])

    if not intervalles:
        intervalles = [0.0]

    return intervalles


# ============================================================
# STATISTIQUES CONNEXIONS INCOMPLÈTES / DDoS
# ============================================================

# Calcule, par minute, le nombre de connexions incomplètes (SYN sans ACK) tous services confondus
def stats_connexions_incompletes_par_minute(table):
    syn_par_dest_minute = Counter()
    ack_par_dest_minute = Counter()

    for e in table:
        dst = cle_destination(e)
        f = e["flags"]
        t = parse_time(e["heure"])
        minute = int(t // 60)
        if "S" in f:
            syn_par_dest_minute[(dst, minute)] += 1
        if "A" in f:
            ack_par_dest_minute[(dst, minute)] += 1

    incompletes_par_minute = Counter()
    for key, nb_syn in syn_par_dest_minute.items():
        nb_ack = ack_par_dest_minute.get(key, 0)
        incompletes = max(nb_syn - nb_ack, 0)
        if incompletes > 0:
            incompletes_par_minute[key] = incompletes

    if not incompletes_par_minute:
        return [0], [0]

    par_minute = Counter()
    for (dst, minute), nb in incompletes_par_minute.items():
        par_minute[minute] += nb

    minutes = sorted(par_minute.keys())
    valeurs = [par_minute[m] for m in minutes]
    return minutes, valeurs

# Calcule, par service (IP:port destination), le nombre de connexions incomplètes
def stats_connexions_incompletes_par_service(table, top_n=10):
    syn_par_dest = Counter()
    ack_par_dest = Counter()

    for e in table:
        dst = cle_destination(e)
        f = e["flags"]
        if "S" in f:
            syn_par_dest[dst] += 1
        if "A" in f:
            ack_par_dest[dst] += 1

    incompletes = []
    for dst, nb_syn in syn_par_dest.items():
        nb_ack = ack_par_dest.get(dst, 0)
        incomplets = max(nb_syn - nb_ack, 0)
        incompletes.append((dst, incomplets))

    incompletes.sort(key=lambda x: x[1], reverse=True)
    if not incompletes:
        incompletes = [(("aucune_ip", "0"), 0)]

    labels = [f"{ip}:{port}" for (ip, port), v in incompletes[:top_n]]
    valeurs = [v for (dst, v) in incompletes[:top_n]]
    return labels, valeurs


# ============================================================
# GÉNÉRATION DES GRAPHIQUES (BAR, HISTO, PIE)
# ============================================================

# Crée un graphique en barres et le sauvegarde dans un fichier image
def plot_bar(labels, values, title, xlabel, ylabel, path):
    plt.figure(figsize=(8, 4))
    plt.bar(range(len(labels)), values)
    plt.xticks(range(len(labels)), labels, rotation=45, ha="right")
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()

# Crée un histogramme et le sauvegarde dans un fichier image
def plot_hist(data, title, xlabel, ylabel, path, bins=20):
    plt.figure(figsize=(8, 4))
    plt.hist(data, bins=bins)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()

# Crée un diagramme circulaire et le sauvegarde dans un fichier image
def plot_pie(labels, values, title, path):
    plt.figure(figsize=(5, 5))
    if sum(values) == 0:
        labels = ["Aucune donnée"]
        values = [1]
    plt.pie(values, labels=labels, autopct="%1.1f%%", startangle=90)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


# ============================================================
# GRAPHIQUES DE SYNTHÈSE
# ============================================================

# Génère les graphes de synthèse (top IP, longueurs, protocoles, requêtes)
def generer_graphiques_synthese(table, output_dir):
    top_src = stats_ip_sources(table)
    if not top_src:
        top_src = [("Aucune IP", 0)]
    labels_src = [ip for ip, n in top_src]
    values_src = [n for ip, n in top_src]
    img_ip_src = os.path.join(output_dir, "ip_sources.png")
    plot_bar(labels_src, values_src,
             "Top IP source", "IP source", "Nombre de paquets", img_ip_src)

    img_requetes = os.path.join(output_dir, "requetes_par_ip.png")
    plot_bar(labels_src, values_src,
             "Nombre de requêtes par IP source",
             "IP source", "Nombre de requêtes", img_requetes)

    top_dst = stats_ip_destinations(table)
    if not top_dst:
        top_dst = [("Aucune IP", 0)]
    labels_dst = [ip for ip, n in top_dst]
    values_dst = [n for ip, n in top_dst]
    img_ip_dst = os.path.join(output_dir, "ip_destinations.png")
    plot_bar(labels_dst, values_dst,
             "Top IP destination", "IP destination", "Nombre de paquets", img_ip_dst)

    lengths = stats_longueurs(table)
    if not lengths:
        lengths = [0]
    img_lengths = os.path.join(output_dir, "longueurs_paquets.png")
    plot_hist(lengths,
              "Distribution de la longueur des paquets",
              "Longueur (octets)", "Nombre de paquets", img_lengths)

    proto_counts = stats_protocoles(table)
    labels_proto = list(proto_counts.keys())
    values_proto = list(proto_counts.values())
    if not labels_proto:
        labels_proto = ["Aucun"]
        values_proto = [1]
    img_proto = os.path.join(output_dir, "protocoles.png")
    plot_pie(labels_proto, values_proto,
             "Répartition des protocoles (par port destination)", img_proto)

    return {
        "img_ip_src": img_ip_src,
        "img_ip_dst": img_ip_dst,
        "img_lengths": img_lengths,
        "img_proto": img_proto,
        "img_requetes": img_requetes,
    }


# ============================================================
# GRAPHIQUES SSH
# ============================================================

# Génère les graphes d'activité SSH (volume par session + répartition des flags)
def generer_graphiques_ssh(table, output_dir):
    sessions = stats_ssh_sessions(table)
    if not sessions:
        sessions = {("aucune_session", "ssh"): {
            "pkts": 0,
            "bytes_total": 0,
            "bytes_client": 0,
            "bytes_server": 0,
        }}

    labels_sess = [f"{src}->{dst}" for (src, dst) in sessions.keys()]
    bytes_client = [s["bytes_client"] for s in sessions.values()]
    bytes_server = [s["bytes_server"] for s in sessions.values()]

    img_ssh_volume = os.path.join(output_dir, "ssh_sessions_volume.png")
    plt.figure(figsize=(8, 4))
    x = range(len(labels_sess))
    plt.bar([i - 0.2 for i in x], bytes_client, width=0.4, label="Client -> Serveur")
    plt.bar([i + 0.2 for i in x], bytes_server, width=0.4, label="Serveur -> Client")
    plt.xticks(list(x), labels_sess, rotation=45, ha="right")
    plt.title("Volume échangé par session SSH")
    plt.xlabel("Session (client -> serveur)")
    plt.ylabel("Octets")
    plt.legend()
    plt.tight_layout()
    plt.savefig(img_ssh_volume)
    plt.close()

    flags_counts = stats_flags_ssh(table)
    labels_flags = list(flags_counts.keys()) or ["Aucun"]
    values_flags = list(flags_counts.values()) or [1]
    img_ssh_flags = os.path.join(output_dir, "ssh_flags.png")
    plot_pie(labels_flags, values_flags,
             "Répartition des flags TCP (SSH)", img_ssh_flags)

    return {
        "img_ssh_volume": img_ssh_volume,
        "img_ssh_flags": img_ssh_flags,
    }


# ============================================================
# GRAPHIQUES SCAN / SYN
# ============================================================

# Génère le graphe des intervalles entre SYN successifs
def generer_graphiques_scan(table, output_dir):
    intervalles = stats_intervalles_syn_par_source(table)
    img_scan_intervalles = os.path.join(output_dir, "scan_intervalles_syn.png")
    plot_hist(intervalles,
              "Intervalles entre SYN successifs (sources les plus actives)",
              "Intervalle (secondes)", "Nombre d'occurrences", img_scan_intervalles)

    return {
        "img_scan_intervalles": img_scan_intervalles,
    }


# ============================================================
# GRAPHIQUES DDoS / CONNEXIONS INCOMPLÈTES
# ============================================================

# Génère les graphes liés aux connexions incomplètes (temps + service)
def generer_graphiques_ddos(table, output_dir):
    minutes, valeurs_minute = stats_connexions_incompletes_par_minute(table)
    img_ddos_incomplets_temps = os.path.join(output_dir, "ddos_incomplets_par_minute.png")
    plt.figure(figsize=(8, 4))
    plt.plot(minutes, valeurs_minute, marker="o")
    plt.title("Connexions incomplètes par minute (vue globale)")
    plt.xlabel("Minute (depuis le début de la capture)")
    plt.ylabel("Nombre de connexions incomplètes")
    plt.tight_layout()
    plt.savefig(img_ddos_incomplets_temps)
    plt.close()

    labels_serv, valeurs_serv = stats_connexions_incompletes_par_service(table)
    img_ddos_incompletes_service = os.path.join(output_dir, "ddos_incompletes_par_service.png")
    plot_bar(labels_serv, valeurs_serv,
             "Connexions incomplètes par service",
             "Destination (IP:port)", "Nombre de connexions incomplètes", img_ddos_incompletes_service)

    return {
        "img_ddos_incomplets_temps": img_ddos_incomplets_temps,
        "img_ddos_incompletes_service": img_ddos_incompletes_service,
    }


# ============================================================
# INTERFACE GRAPHIQUE (GUI) ET ORCHESTRATION
# ============================================================

# Affiche un court résumé dans la zone de texte Tkinter après traitement
def afficher_resultat(texte_resultat, chemin_csv, chemin_html, stats, output_dir):
    texte_resultat.config(state="normal")
    texte_resultat.delete("1.0", tk.END)
    texte_resultat.insert(
        tk.END,
        f"Fichiers générés dans : {output_dir}\n\n"
        f"- {os.path.basename(chemin_csv)}\n"
        f"- {os.path.basename(chemin_html)}\n\n"
        f"Paquets totaux : {stats['nb_total']}\n"
        f"Octets totaux : {stats['octets_total']}\n"
    )
    texte_resultat.config(state="disabled")

# Chaîne complète : choix fichier -> analyse -> graphes -> HTML -> affichage
def traiter_fichier(texte_resultat):
    chemin = choisir_fichier_reseau()
    if not chemin:
        return

    lignes = lire_fichier(chemin)
    table = construire_tableau(lignes)

    if not table:
        messagebox.showwarning("Erreur", "Aucun paquet IP valide n'a été trouvé dans ce fichier.")
        return

    output_dir = get_output_dir()
    chemin_csv = os.path.join(output_dir, "reseau_analyse.csv")
    chemin_html = os.path.join(output_dir, "rapport_reseau.html")

    ecrire_csv(table, chemin_csv)
    stats = analyser_globale(table)

    imgs_synthese = generer_graphiques_synthese(table, output_dir)
    imgs_ssh = generer_graphiques_ssh(table, output_dir)
    imgs_scan = generer_graphiques_scan(table, output_dir)
    imgs_ddos = generer_graphiques_ddos(table, output_dir)

    generer_html(
        table,
        stats,
        chemin_html,
        nom_source=chemin,
        **imgs_synthese,
        **imgs_ssh,
        **imgs_scan,
        **imgs_ddos,
    )

    afficher_resultat(texte_resultat, chemin_csv, chemin_html, stats, output_dir)
    messagebox.showinfo(
        "Terminé",
        f"Traitement terminé.\nTous les fichiers ont été générés dans :\n{output_dir}"
    )
    webbrowser.open_new_tab(chemin_html)

# Crée la fenêtre Tkinter principale avec les boutons et la zone de texte
def main():
    global fenetre
    fenetre = tk.Tk()
    fenetre.title("Traitement réseau - SAÉ1.5")
    fenetre.geometry("700x320")

    texte_resultat = tk.Text(fenetre, height=10, width=80)
    texte_resultat.pack(padx=10, pady=10)
    texte_resultat.config(state="disabled")

    btn_choisir = tk.Button(
        fenetre,
        text="Choisir un fichier texte réseau",
        command=lambda: traiter_fichier(texte_resultat)
    )
    btn_choisir.pack(pady=10)

    btn_quitter = tk.Button(fenetre, text="Quitter", command=fenetre.quit)
    btn_quitter.pack(pady=10)

    fenetre.mainloop()

# Point d'entrée du script (lancement de la GUI)
if __name__ == "__main__":
    main()