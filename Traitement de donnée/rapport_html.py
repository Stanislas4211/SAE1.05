#!/usr/bin/env python3
# rapport_html.py
import markdown

    # 1 --  Façonnage du texte Markdown
def generer_markdown_rapport(
    table,
    stats,
    nom_source,
    img_ip_src,
    img_ip_dst,
    img_ports,
    img_lengths,
    img_proto,
    img_requetes,
    img_ssh_sessions,
    img_ssh_volume,
    img_ssh_flags,
    img_scan_ports,
    img_scan_syn_ratio,
    img_scan_intervalles,
    img_ddos_ratio,
    img_ddos_incomplets_temps,
    img_ddos_incomplets_service,
    img_sql_hotes,
    img_sql_sources,
):
    
    #Contenu de la page
    md = f"""# Analyse des traces réseau

    
## Résumé du fichier

- **Fichier analysé** : `{nom_source}`
- **Nombre total de paquets analysés** : {stats['nb_total']}
- **Volume total** : {stats['octets_total']} octets


## Vue synthétique du trafic

### Top IP source

![Top IP source]({img_ip_src})  
_Identifie les machines qui émettent le plus de requêtes._

### Top IP destination

![Top IP destination]({img_ip_dst})  
_Montre quelles machines reçoivent le plus de trafic._

### 10 ports les plus utilisés

![Ports les plus utilisés]({img_ports})  
_Permet de voir les services les plus sollicités._

### Distribution de la longueur des paquets

![Longueur des paquets]({img_lengths})  
_Aide à distinguer petits paquets (scans) et flux volumineux._

### Nombre de requêtes par IP source

![Nombre de requêtes]({img_requetes})  
_Résume le nombre total de requêtes par IP source._

### Répartition des protocoles

![Répartition des protocoles]({img_proto})  
_Indique si le trafic est conforme à l’usage prévu._


## Activité SSH

### Sessions SSH approximées

![Sessions SSH]({img_ssh_sessions})  
_Nombre de paquets par couple client → serveur._
_Permet de voir si une session envoie beaucoup plus de paquets que les autres_

### Volume échangé par session SSH

![Volume SSH par session]({img_ssh_volume})  
_Compare les octets client → serveur et serveur → client._
_Permet d’identifier un déséquilibre fort, ce qui peut indiquer une surcharge, un téléchargement massif, ou une session bloquée qui n’envoie presque rien dans un sens._

### Répartition des flags TCP (SSH)

![Flags SSH]({img_ssh_flags})  
_Permet de repérer des terminaisons brutales ou anormales._


## Scan de ports par IP source

### Ports distincts contactés en SYN

![Ports distincts en SYN]({img_scan_ports})  
_Une IP qui envoie des SYN vers beaucoup de ports ressemble fortement à un scan de ports ou à un outil de découverte de services._

### Taux de SYN sans ACK

![Taux de SYN sans ACK]({img_scan_syn_ratio})  
_Un taux proche de 1 est typique de scans furtifs (envoie un SYN sur plein de ports, ne répond pas à l’ACK éventuel, et n’établit jamais de vraie connexion)._

### Intervalles entre SYN successifs

![Intervalles entre SYN]({img_scan_intervalles})  
_Un rythme régulier rapide est typique d’un outil automatique._


## Connexions incomplètes et risques de DDoS

### Ratio SYN / SYN‑ACK par destination

![Ratio SYN / SYN-ACK]({img_ddos_ratio})  
_Un ratio élevé peut révéler un début de flood ou un serveur saturé qui ne répond plus correctement._

### Connexions incomplètes par minute

![Connexions incomplètes par minute]({img_ddos_incomplets_temps})  
_Permet de repérer des pics soudains._
_Un point avec un nombre très élevé indique un pic soudain de connexions qui n’aboutissent pas, ce qui peut correspondre à un scan massif, un bot, ou un service qui répond mal._

### Connexions incomplètes par service

![Connexions incomplètes par service]({img_ddos_incomplets_service})  
_Identifie les services les plus touchés._


## Requêtes SQL suspectes

### Hôtes / URLs ciblés

![Hôtes ciblés par SQL]({img_sql_hotes})  
_Liste les hôtes apparaissant dans des motifs d’injection SQL._

### Requêtes SQL suspectes par IP source

![Sources SQL suspectes]({img_sql_sources})  
_Révèle les machines à l’origine de requêtes suspectes._
"""
    return md  #Renvoie la chaîne Markdown complète contenant tout le rapport.

  #Fonction chargée de produire le fichier HTML final.
    #Elle reçoit les mêmes informations que generer_markdown_rapport plus le chemin_html (où écrire le fichier HTML généré).
def generer_html(
    table,
    stats,
    chemin_html,
    nom_source,
    img_ip_src,
    img_ip_dst,
    img_ports,
    img_lengths,
    img_proto,
    img_requetes,
    img_ssh_sessions,
    img_ssh_volume,
    img_ssh_flags,
    img_scan_ports,
    img_scan_syn_ratio,
    img_scan_intervalles,
    img_ddos_ratio,
    img_ddos_incomplets_temps,
    img_ddos_incompletes_service,
    img_sql_hotes,
    img_sql_sources,
):

  #On récupère la fonction réalisée juste au-dessus pour récupérer dans md_text la version MarkDown du rapport, que l'on peut convertir en HTML (Voir la suite du code)
    md_text = generer_markdown_rapport(
        table,
        stats,
        nom_source,
        img_ip_src,
        img_ip_dst,
        img_ports,
        img_lengths,
        img_proto,
        img_requetes,
        img_ssh_sessions,
        img_ssh_volume,
        img_ssh_flags,
        img_scan_ports,
        img_scan_syn_ratio,
        img_scan_intervalles,
        img_ddos_ratio,
        img_ddos_incomplets_temps,
        img_ddos_incompletes_service,
        img_sql_hotes,
        img_sql_sources,
    )

    # 2 -- Conversion Markdown -> HTML
    html_body = markdown.markdown(md_text)

    # 3 -- Encapsulement dans une page HTML
    # HTML avec Bootswatch + mise en page
    html_page = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Analyse réseau</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet"
        href="https://bootswatch.com/5/journal/bootstrap.min.css">
  <style>
    body {{
      padding-top: 70px;
    }}
    .markdown-body h1 {{
      margin-bottom: 1.5rem;
      text-align: center;
    }}
    .markdown-body h2 {{
      margin-top: 2rem;
      margin-bottom: 1rem;
      border-bottom: 1px solid #dee2e6;
      padding-bottom: .4rem;
    }}
    .markdown-body h3 {{
      margin-top: 1.5rem;
      margin-bottom: .8rem;
    }}
    .markdown-body img {{
      display: block;
      max-width: 100%;
      height: auto;
      margin: 0 auto 0.5rem auto;
    }}
    .markdown-body em {{
      display: block;
      text-align: center;
      color: #6c757d;
      margin-bottom: 1rem;
    }}
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-primary fixed-top">
    <div class="container-fluid">
      <span class="navbar-brand mb-0 h1">Analyse des traces réseau</span>
    </div>
  </nav>

  <main class="container my-4">
    <div class="card shadow-sm">
      <div class="card-body markdown-body">
        {html_body}
      </div>
    </div>
  </main>

  <footer class="text-center text-muted py-3">
    <small>SAÉ1.5 - Traitement des données réseau</small>
  </footer>
</body>
</html>
"""

    # 4) Écrire le fichier HTML final
    with open(chemin_html, "w", encoding="utf-8") as f:
        f.write(html_page)