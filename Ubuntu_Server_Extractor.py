```python

class LogViewer:
    
    ## Objet LogViewer permet decalculer et naviguer rapidement entre les data
    ## issues des logs du serveur Ubuntu 16
    ## file = chemin d'accès du fichier log (ex: 'folder/auth.log')
    ## server = nom du serveur tel qu'il apparaît dans le log (ex: 'vpsXXXXX')
    
    def __init__(self, file, server):
        
        # import des modules necessaires a l'instanciation
        import pycountry, re, geocoder
        import pandas as pd
        
        # Definition des variables de classe
        self.server = server
        self.file = file
        self.data = log_to_df(file)
        self.ip_list = ip_extract(self.data)
        self.countries = country_extract(self.ip_list)

    def log_to_df(self, file):
    
        data = pd.DataFrame.from_csv(file, header=None, sep=']:')
        data.reset_index(inplace=True)
        #data[0] = data[0].str.replace('vps95659(.)*', '', case=False)
        data[0] = data[0].str.replace(server+'(.)*', '', case=False)   
        data['IP'] = data[1].str.extract(r'([0-9]+(?:\.[0-9]+){3})')
        data.dropna(inplace=True)
    
        return data

    def ip_extract(self, df):
    
        ip_list = pd.DataFrame(df['IP'].value_counts())
        ip_list.reset_index(inplace=True)
        ip_list.columns = ['IP', 'Freq']
        ip_list.drop(ip_list[ip_list.IP == '0.0.0.0'].index, inplace=True)
        ip_list['City'] = ip_list['IP'].apply(lambda x: get_loc(x).city)
        ip_list['Country'] = ip_list['IP'].apply(lambda x: code_to_country(get_loc(x).country))
    
        return ip_list

    def get_loc(self, ip):

        loc = geocoder.ip(ip)
        admin = geocoder.ip('me').ip
        if loc != admin:    
            try:
                return loc
            except:
                return "NaN"

    def code_to_country(self, country_code):
        ## Convertit un code ISO 3166 en nom courant
        return pycountry.countries.get(alpha_2=country_code).name


    def country_extract(self, ip_df):
    
        country_count = ip_df.groupby('Country').sum().sort_values(by='Freq', ascending=False).sum()
        return country_count

```
