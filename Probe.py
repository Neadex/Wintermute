
# coding: utf-8

import os
import socket, struct, time, ctypes, sys
import pandas as pd
from sklearn.preprocessing import normalize
from sklearn.preprocessing import Imputer
from sklearn.externals import joblib


## Lancement de la probe ##


def main():


    # fonction de boot du scanner

    print("\n\n ----- Scanner started ----- \n")
    print("Use CTRL+C to stop the scanner\n\n")
    print("Scanner take some time to stop. No need for multiple keypresses.\n\n")
    switcher = True
    while switcher:
        try:
            start = time.time()
            snif = sniffer()
            if decision(snif) == 'Legit':
                print('Authorized request...'+time.strftime("Received on %H:%M:%S", time.gmtime()))
                end = time.time()
            else:
                print('!!! Attack detected !!!')
        except KeyboardInterrupt:
            end = time.time()
            elapsed = end - start
            print("Time elapsed :", elapsed, "\n")
            switcher = False
            break



def sniffer():

    ## Fonction principale : sniff les packets sur le réseau local, filtre les TCP

    # Creation du socket d'ecoute
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)

    # list comprehension qui recupere l'adresse locale non virtuelle (127.0.0.1)
    local_ip = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
    s.bind((local_ip, 0))
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

    while True:
    # Boucle infinie d'execution du sniffer local
        try:
            start_time = time.time()
            data = s.recvfrom(10000) # récupération du paquet entier
            ip1 = data[0][0:20]
            ip2 = struct.unpack('!BBHHHBBH4s4s', ip1)
            version_ihl = ip2[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            ip2_length = ihl * 4
            ttl = ip2[5]
            protocol = ip2[6]
            s_addr = socket.inet_ntoa(ip2[8])
            d_addr = socket.inet_ntoa(ip2[9])

            tcp_header = data[0][ip2_length:ip2_length+20]
            try :
                tcph = struct.unpack('!HHLLBBHHH' , tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                try:
                    # Récupère le service utilisant la connexion en fonction du port utilisé (faiblesse : attaques utilisant des services "exotiques" utilisant des ports spécifiques (ex: reverse-payloads))
                    service = socket.getservbyport(dest_port)
                except:
                    continue
                if protocol == 6: # récupération des TCP (id = 6) seulement
                    targ_data = [source_port, dest_port, service]
                    targ_data = one_row_dummies(preprocess(targ_data))
                    target = targ_data.loc[0]
                    return target

                    continue
                else:
                    continue
            except:
                continue
        except KeyboardInterrupt:
            # CTRL+C ferme le socket, qui produit une erreur sur la fonction decision()
            break



### PARTIE LIVE ###


def preprocess(sniff_list):
    # Transforme une liste sniffée en dataframe avec les colonnes integrees
    # Merge des http et https. Note : Les attaques MITM sur https passent par une conversion du protocole en http
    # Permet de structurer les data pour intégrer le dataframe créé via le NSL-KDD
    parsed_pkt = []
    for e in range(len(sniff_list)):
        if sniff_list[e] == 'https':
            protocol = "http"
            parsed_pkt.append(protocol)
        else:
            parsed_pkt.append(sniff_list[e])

    df = pd.DataFrame(parsed_pkt, index = ['src_bytes', 'dst_bytes', 'service']).transpose()
    return df

def one_row_dummies(raw_df):
    # Converti les var catégorielles en dummies pour 1 seule row
    raw_df.reset_index(inplace=True)
    raw_df.drop('index', inplace=True, axis=1)
    raw_df.insert(2, "auth", 0.0)

    raw_df['pop_3'] = 0.0
    raw_df['smtp'] = 0.0
    raw_df['telnet'] = 0.0
    raw_df.columns = ['src_bytes', 'dst_bytes', 'auth', 'http', 'pop_3', 'smtp', 'telnet']
    raw_df.loc[raw_df['http'] == 'http', 'http'] = 1
    return raw_df


def decision(row):

    # Prend une row en arg, la reshape, la normalise et renvoie la décision en str
    # Normlisation strictement identique à l'entraînement du modèle


    # recuperation du chemin relatif d'execution du script
    abspath = os.path.abspath(__file__)
    # recuperation du dossier d'execution du script
    dname = os.path.dirname(abspath)
    # changement du working dir
    os.chdir(dname)
    # load du classifeur
    clf = joblib.load('Light_TCP_clf\\Light_TCP_clf.pkl')
    try:
        test_data = row.values.reshape(1, -1)
    except AttributeError:
        # Si CTRL+C est utilisé, test_data devient NoneType, et row.values.reshape(1, -1) retourne une erreur, executant le bloc except AttributeError
        # Le bloc AttributeError est le seul moyen d'interrompre le scanner (en dehors de ctrl+pause / ctrl+break)
        sys.exit('\n\n\n ----- Scanner stopped ----- ')
    imp = Imputer(missing_values='NaN', strategy='median', axis=0)
    imp.fit(test_data)
    test_data = imp.transform(test_data)
    test_data = normalize(test_data)
    if clf.predict(test_data) == -1:
        return 'Legit'
    if clf.predict(test_data) == 1:
        return 'Attack detected'

main()
