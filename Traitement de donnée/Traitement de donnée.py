#!/usr/bin/env python3
# Traitement de donnée.py

import tkinter as tk
from tkinter import filedialog, messagebox
import re
import csv
import webbrowser
from collections import Counter, defaultdict
import os
import matplotlib.pyplot as plt

from rapport_html import generer_html


# =======================
#    Répertoire de sortie
# =======================

def get_output_dir():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(base_dir, "Fichier renvoyé")
    os.makedirs(out_dir, exist_ok=True)
    return out_dir



# =======================
#    Sélection du fichier
# =======================

#ouvre la boîte de dialogue pour choisir un fichier
def choisir_fichier_reseau():
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier texte réseau",
        filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")]
    )
    return chemin_fichier

#lit ce fichier et renvoie la liste de toutes les lignes.
def lire_fichier(chemin):
    with open(chemin, "r", encoding="utf-8") as f:
        return [l.rstrip("\n") for l in f]



# =======================
#    Parsing des lignes
#      Le parsing est le processus qui consiste à analyser une suite de symboles (texte, code, données) pour en dégager la structure et en extraire des informations exploitables par une machine.
# =======================

#transformer chaque ligne brute de tcpdump en une ligne structurée.
REG_IP = re.compile(
    r'^(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<src>[\w\.-]+)\.(?P<src_port>[\w\d]+)\s*>\s*'
    r'(?P<dst>[\w\.-]+)\.(?P<dst_port>[\w\d]+):\s*'
    r'Flags\s+\[(?P<flags>[^\]]*)\].*?'
    r'length\s+(?P<length>\d+)'
)

#sépare un nom du type machine.test.443 en deux 
def split_host_port(nom):
    parts = nom.split(".")
    if len(parts) >= 2:
        host = ".".join(parts[:-1])
        port = parts[-1]
    else:
        host = nom
        port = "vide"
    return host, port

#essaie de matcher la ligne avec REG_IP puis construit un dictionnaire Python contenant les résultats 
def ligne_vers_dict(ligne):
    m = REG_IP.match(ligne)
    if not m:
        return None
    d = m.groupdict()

    src_full = d["src"]
    dst_full = d["dst"]
    src_host, src_port2 = split_host_port(src_full)
    dst_host, dst_port2 = split_host_port(dst_full)

    return {
        "heure": d["time"],
        "src_host": src_host,
        "src_port": d.get("src_port") or src_port2,
        "dst_host": dst_host,
        "dst_port": d.get("dst_port") or dst_port2,
        "flags": d["flags"],
        "length": int(d["length"]),
    }

#applique ligne_vers_dict à toutes les lignes puis renvoie une liste de dictionnaires (mon tableau d’événements)
def construire_tableau(lignes):
    table = []
    for l in lignes:
        evt = ligne_vers_dict(l)
        if evt is not None:
            table.append(evt)
    return table

#écrit ce tableau dans un fichier reseau_analyse.csv
def ecrire_csv(table, chemin_csv):
    if not table:
        return
    champs = ["heure", "src_host", "src_port", "dst_host", "dst_port", "flags", "length"]
    with open(chemin_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=champs, delimiter=";")
        w.writeheader()
        for e in table:
            w.writerow(e)

#calcule le nombre de packets et la somme total des octets (renvoie ces deux valeur dans un dictionnaire)
def analyser_globale(table):
    total = len(table)
    total_octets = sum(e["length"] for e in table)
    return {
        "nb_total": total,
        "octets_total": total_octets,
    }



# =======================
#    Calcul des statistiques pour les graphes
#      Statistiques génériques
# =======================

#Regarde les top IP sources
def stats_ip_sources(table, top_n=10):
    c = Counter(e["src_host"] for e in table)
    return c.most_common(top_n)

#Regarde les top IP destinations
def stats_ip_destinations(table, top_n=10):
    c = Counter(e["dst_host"] for e in table)
    return c.most_common(top_n)

#Regarde les top ports de destination
def stats_ports(table, top_n=10):
    c = Counter(str(e["dst_port"]) for e in table)
    return c.most_common(top_n)

#liste toutes les longueurs de paquets.
def stats_longueurs(table):
    return [e["length"] for e in table]

#compte approximatif des protocoles (DNS / SSH / HTTP / HTTPS / AUTRES) suivant le port.
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



# =======================
#    Calcul des statistiques pour les graphes
#      SSH 
# =======================

#parcourt la liste de paquets et renvoie seulement ceux qui utilisent le port 22 (port ssh)
def filtrer_ssh(table):
    ssh_pkts = []
    for e in table:
        if (str(e["src_port"]) == "22" or str(e["dst_port"]) == "22"
            or e["src_port"] == "ssh" or e["dst_port"] == "ssh"):
            ssh_pkts.append(e)
    return ssh_pkts

#Cette fonction calcule des statistiques de trafic par session SSH (couple client ↔ serveur), en comptant les paquets et octets échangés côté client et côté serveur.
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

#Ce programme compte combien de fois chaque flag TCP apparaît dans les paquets SSH et renvoie ces statistiques sous forme de compteur.
def stats_flags_ssh(table):
    ssh_pkts = filtrer_ssh(table)
    counts = Counter()
    for e in ssh_pkts:
        for ch in e["flags"]:
            if ch.isalpha():
                counts[ch] += 1
    return counts



# =======================
#    Calcul des statistiques pour les graphes
#      Scan de ports (SYN)
# =======================

#Cette fonction teste si un paquet est un SYN “pur” (début de connexion TCP) et non un SYN‑ACK.
def est_syn(e):
    f = e["flags"]
    return "S" in f and "A" not in f 

#Cette fonction calcule, pour chaque IP source, combien de ports de destination différents elle a contactés avec des paquets SYN « purs », puis renvoie le top des IP les plus “scanneuses”.
def stats_ports_distincts_par_source(table, top_n=10):
    ports_par_src = defaultdict(set)
    for e in table:
        if est_syn(e):
            ports_par_src[e["src_host"]].add(str(e["dst_port"]))
    counts = [(src, len(ports)) for src, ports in ports_par_src.items()]
    counts.sort(key=lambda x: x[1], reverse=True)
    if not counts:
        counts = [("Aucune IP", 0)]
    return counts[:top_n]

#Cette fonction calcule, pour chaque IP source, le taux de paquets SYN qui ne sont pas suivis d’ACK, puis renvoie le top des IP les plus suspectes
def stats_syn_sans_ack_par_source(table, top_n=10):
    syn_counts = Counter()
    ack_counts = Counter()

    for e in table:
        src = e["src_host"]
        f = e["flags"]
        if "S" in f:
            syn_counts[src] += 1
        if "A" in f:
            ack_counts[src] += 1

    ratios = []
    for src, nb_syn in syn_counts.items():
        nb_ack = ack_counts.get(src, 0)
        if nb_syn == 0:
            ratio = 0.0
        else:
            ratio = max(nb_syn - nb_ack, 0) / nb_syn
        ratios.append((src, ratio))

    ratios.sort(key=lambda x: x[1], reverse=True)
    if not ratios:
        ratios = [("Aucune IP", 0.0)]
    return ratios[:top_n]

#Cette fonction convertit une heure au format "HH:MM:SS" en nombre de secondes écoulées depuis 00:00:00
def parse_time(hhmmss):
    h, m, s = hhmmss.split(":")
    s = float(s)
    return int(h) * 3600 + int(m) * 60 + s

#Cette fonction calcule les intervalles de temps entre paquets SYN successifs pour les sources les plus actives, afin d’analyser le rythme des scans / connexions
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



# =======================
#    Calcul des statistiques pour les graphes
#      Connexions incomplètes / DDoS
# =======================

def cle_destination(e):
    return (e["dst_host"], str(e["dst_port"]))


def stats_ratio_syn_synack_par_destination(table, top_n=10):
    syn_counts = Counter()
    synack_counts = Counter()

    for e in table:
        dst = cle_destination(e)
        f = e["flags"]
        if "S" in f and "A" not in f:
            syn_counts[dst] += 1
        if "S" in f and "A" in f:
            synack_counts[dst] += 1

    ratios = []
    for dst, nb_syn in syn_counts.items():
        nb_synack = synack_counts.get(dst, 0)
        if nb_syn == 0:
            ratio = 0.0
        else:
            ratio = max(nb_syn - nb_synack, 0) / nb_syn
        ratios.append((dst, ratio))

    ratios.sort(key=lambda x: x[1], reverse=True)
    if not ratios:
        ratios = [(("aucune_ip", "0"), 0.0)]

    labels = [f"{ip}:{port}" for (ip, port), r in ratios[:top_n]]
    values = [r for (dst, r) in ratios[:top_n]]
    return labels, values


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



# =======================
#    Calcul des statistiques pour les graphes
#      SQL suspectes 
# =======================

SQL_MOTIFS = ["union select", " or 1=1", " or '1'='1", ' or "1"="1']    


def extraire_ip_source_depuis_ligne(ligne):
    m = re.search(r"(\d{1,3}\.){3}\d{1,3}", ligne)
    return m.group(0) if m else "inconnue"


def extraire_hote_depuis_ligne(ligne):
    m_host = re.search(r"[Hh]ost:\s*([^\s]+)", ligne)
    if m_host:
        return m_host.group(1)

    m_ip = re.search(r">\s*([\w\.-]+)\.", ligne)
    if m_ip:
        return m_ip.group(1)

    return "inconnu"


def stats_sql_suspectes(lignes_brutes, top_n=10):
    hote_counts = Counter()
    src_counts = Counter()

    for l in lignes_brutes:
        l_low = l.lower()
        if any(m in l_low for m in SQL_MOTIFS):
            src_ip = extraire_ip_source_depuis_ligne(l)
            hote = extraire_hote_depuis_ligne(l)
            hote_counts[hote] += 1
            src_counts[src_ip] += 1

    top_hotes = hote_counts.most_common(top_n)
    if not top_hotes:
        top_hotes = [("aucun_hote", 0)]

    top_src = src_counts.most_common(top_n)
    if not top_src:
        top_src = [("aucune_ip", 0)]

    return top_hotes, top_src



# =======================
#    Génération des graphes
# =======================

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


def plot_hist(data, title, xlabel, ylabel, path, bins=20):
    plt.figure(figsize=(8, 4))
    plt.hist(data, bins=bins)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


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

    top_ports = stats_ports(table)
    if not top_ports:
        top_ports = [("aucun", 0)]
    labels_ports = [p for p, n in top_ports]
    values_ports = [n for p, n in top_ports]
    img_ports = os.path.join(output_dir, "ports_top10.png")
    plot_bar(labels_ports, values_ports,
             "10 ports les plus utilisés", "Port destination", "Nombre de paquets", img_ports)

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
        "img_ports": img_ports,
        "img_lengths": img_lengths,
        "img_proto": img_proto,
        "img_requetes": img_requetes,
    }


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
    pkts_sess = [s["pkts"] for s in sessions.values()]
    bytes_client = [s["bytes_client"] for s in sessions.values()]
    bytes_server = [s["bytes_server"] for s in sessions.values()]

    img_ssh_sessions = os.path.join(output_dir, "ssh_sessions_nb.png")
    plot_bar(labels_sess, pkts_sess,
             "Paquets par session SSH (approx.)",
             "Session (client -> serveur)", "Nombre de paquets", img_ssh_sessions)

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
        "img_ssh_sessions": img_ssh_sessions,
        "img_ssh_volume": img_ssh_volume,
        "img_ssh_flags": img_ssh_flags,
    }


def generer_graphiques_scan(table, output_dir):
    ports_distincts = stats_ports_distincts_par_source(table)
    labels_ports_scan = [src for src, n in ports_distincts]
    values_ports_scan = [n for src, n in ports_distincts]
    img_scan_ports = os.path.join(output_dir, "scan_ports_distincts.png")
    plot_bar(labels_ports_scan, values_ports_scan,
             "Ports distincts contactés en SYN (par IP source)",
             "IP source", "Nombre de ports distincts", img_scan_ports)

    syn_ratios = stats_syn_sans_ack_par_source(table)
    labels_syn_ratio = [src for src, r in syn_ratios]
    values_syn_ratio = [r for src, r in syn_ratios]
    img_scan_syn_ratio = os.path.join(output_dir, "scan_syn_sans_ack.png")
    plot_bar(labels_syn_ratio, values_syn_ratio,
             "Taux de SYN sans ACK (par IP source)",
             "IP source", "Proportion de SYN sans ACK", img_scan_syn_ratio)

    intervalles = stats_intervalles_syn_par_source(table)
    img_scan_intervalles = os.path.join(output_dir, "scan_intervalles_syn.png")
    plot_hist(intervalles,
              "Intervalles entre SYN successifs (sources les plus actives)",
              "Intervalle (secondes)", "Nombre d'occurrences", img_scan_intervalles)

    return {
        "img_scan_ports": img_scan_ports,
        "img_scan_syn_ratio": img_scan_syn_ratio,
        "img_scan_intervalles": img_scan_intervalles,
    }


def generer_graphiques_ddos(table, output_dir):
    labels_ratio, valeurs_ratio = stats_ratio_syn_synack_par_destination(table)
    img_ddos_ratio = os.path.join(output_dir, "ddos_ratio_syn_synack.png")
    plot_bar(labels_ratio, valeurs_ratio,
             "Ratio SYN / SYN-ACK par destination",
             "Destination (IP:port)", "Proportion de SYN sans SYN-ACK", img_ddos_ratio)

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
        "img_ddos_ratio": img_ddos_ratio,
        "img_ddos_incomplets_temps": img_ddos_incomplets_temps,
        "img_ddos_incompletes_service": img_ddos_incompletes_service,
    }


def generer_graphiques_sql(lignes_brutes, output_dir):
    top_hotes, top_src = stats_sql_suspectes(lignes_brutes)

    labels_hotes = [h for h, n in top_hotes]
    valeurs_hotes = [n for h, n in top_hotes]
    img_sql_hotes = os.path.join(output_dir, "sql_hotes.png")
    plot_bar(labels_hotes, valeurs_hotes,
             "Top hôtes associés à des motifs SQL",
             "Hôte / URL", "Nombre de requêtes suspectes", img_sql_hotes)

    labels_src = [ip for ip, n in top_src]
    valeurs_src = [n for ip, n in top_src]
    img_sql_sources = os.path.join(output_dir, "sql_sources.png")
    plot_bar(labels_src, valeurs_src,
             "Requêtes SQL suspectes par IP source",
             "IP source", "Nombre de requêtes suspectes", img_sql_sources)

    return {
        "img_sql_hotes": img_sql_hotes,
        "img_sql_sources": img_sql_sources,
    }



# =======================
#    Génération du rapport et GUI (Interface Graphique Utilisateur)
# =======================

#affiche dans la zone de texte Tkinter un petit rapport
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

#prend un fichier de capture réseau choisi par l’utilisateur, lance toute l’analyse, génère les fichiers de sortie puis affiche et ouvre le rapport
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
    imgs_sql = generer_graphiques_sql(lignes, output_dir)

    generer_html(
        table,
        stats,
        chemin_html,
        nom_source=chemin,
        **imgs_synthese,
        **imgs_ssh,
        **imgs_scan,
        **imgs_ddos,
        **imgs_sql,
    )

    afficher_resultat(texte_resultat, chemin_csv, chemin_html, stats, output_dir)
    messagebox.showinfo(
        "Terminé",
        f"Traitement terminé.\nTous les fichiers ont été générés dans :\n{output_dir}"
    )
    # Ouvrir le rapport HTML dans le navigateur par défaut
    webbrowser.open_new_tab(chemin_html)

# lance l’interface graphique Tkinter de l'outil d’analyse réseau : une petite fenêtre avec un bouton pour choisir un fichier de capture et un autre pour quitter.
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


if __name__ == "__main__":
    main()
