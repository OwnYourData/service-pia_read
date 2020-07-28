# <img src="https://github.com/OwnYourData/service-pia_read/raw/master/assets/service.png" width="92"> PIA Read Service    
The PIA Read Service provides convenience functions to access the OwnYourData Data Vault. It reads data from a specific repo and optionally decrypts the data.    

more infos about OwnYourData: https://www.ownyourdata.eu    
OwnYourData Data Vault: https://data-vault.eu/en    
Developer information: https://www.ownyourdata.eu/en/developer/    
Docker Image: https://hub.docker.com/r/oydeu/srv-pia_read    

&nbsp;    

## Example
Use the following example to retrieve data from the `oyd.location` Repo:    
```
echo '{"pia_url":"https://data-vault.eu", 
       "app_key": "<insert Identifier from OwnYourData Base plugin>", 
       "app_secret": "<insert Secret from OwnYourData Base plugin>", 
       "repo": "oyd.location", 
       "password": "<your data vault password>"}' | \
docker run -i --rm oydeu/srv-pia_read /bin/run.sh
```    

&nbsp;    

# Improve the PIA Read Service
Please report bugs and suggestions for new features using the [GitHub Issue-Tracker](https://github.com/OwnYourData/srv-pia_read/issues) and follow the [Contributor Guidelines](https://github.com/twbs/ratchet/blob/master/CONTRIBUTING.md).

If you want to contribute, please follow these steps:

1. Fork it!
2. Create a feature branch: `git checkout -b my-new-feature`
3. Commit changes: `git commit -am 'Add some feature'`
4. Push into branch: `git push origin my-new-feature`
5. Send a Pull Request

&nbsp;    

## Lizenz

[MIT License 2020 - OwnYourData.eu](https://raw.githubusercontent.com/OwnYourData/srv-pia_read/master/LICENSE)