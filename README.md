# kvkit readme

kvkit is a tiny Express app that provides big Splunk KV store management capabilities **and** fancy Splunk-integrated web forms. 

The instructions that follow assume a basic understanding of Linux. Steps 1-17 will get you up and running. Steps 18-23 introduce key concepts pertaining to form creation and related goodness. 

## Splunk configuration
1. Create `kvkit_rest` account on your search head or search head cluster. This account will be used for all kvkit interaction between kvkit and the Splunk REST API. Ensure that the account has all REST capabilities. 
2. Create a new index named `kvkit`. This index will contain all kvkit application-level logging. 
3. Create a new HTTP Event Collector configuration with a default index of `kvkit`.
4. Create a role named `kvkit_admin` without any capabilities or inheritance. Any Splunk user assigned to this role will have access to the kvkit application.  Users are not provisioned in kvkit.

## kvkit Installation & Configuration
kvkit can be installed anywhere, but we'll assume you're installing at `/opt/kvkit`. 

5. Install the latest stable version of [node.js](https://nodejs.org/).
6. _Optional_ Install [pm2](https://www.npmjs.com/package/pm2). You can run kvkit with node directly, but pm2 is the bee's knees and/or the cat's pajamas. 
7. Clone the kvkit repo to `/opt`:

```bash
cd /opt 
git clone https://github.com/fancherblack/kvkit.git 
```

8. Rename the `config_changeme` directory to `config`.  This folder contains the empty configuration files (JSON) needed to complete the setup. 

```bash
cd /opt/kvkit
mv config_changeme config
```

9. Create a `cert` directory within the kvkit application directory. Generate and install an SSL certificate in `cert` as follows:  

```bash
cd /opt/kvkit/cert
openssl genrsa 2048 > host.key
openssl req -new -x509 -nodes -sha256 -days 365 -key host.key -out host.crt
```

Update `config/ssl.json` with your SSL information. 

```json

{
    "cert":"/opt/kvkit/cert/host.crt",
    "key":"/opt/kvkit/cert/host.key"
}
```


10. Install required node modules and dependencies:  

```bash
npm install -d
```

11. Update `config/splunk.json` with your search head hostname (`hostname`), REST port (`rest_port`), logging destination, and HTTP Event Collector port (`hec_port`).

```json
{
    "hostname": "splunk.yourcompany.com",
    "rest_port": 8089,
    "logging_hostname": "where_hec_lives.yourcompany.com",
    "hec_port": 8088
}
```

12. Update `config/credentials.json` with your REST account (`kvkit_rest`) and REST account password (`password`) from step 1. Add the HTTP Event Collector token value  (`hecToken`) from step 3.

```json
{
    "username": "kvkit_rest",
    "password": "pass",
    "hecToken": "aaaaaaaaa-1111-2222-3333-abc123abc123"
}
```

13. Update `config/server.json` with the kvkit server IP address (`addr`) and application port. The defaults shown below listen on all IP addresses and port 8008.

```json
{
    "addr":"0.0.0.0",
    "port":8008
    "proxy":""
}
```

The `proxy` setting has been deprecated and will be removed in future versions. (It was associated with the license server configuration, which went the way of the dodo bird.)

14. Update `config/email.json` with your email server details. This will allow you to configure email notifications on form submissions.

### SMTP
If you are using a SMTP server that requires authentication, configure `email.json` like so: 

```json
{
    "host": "smtp.yourcompany.com",
    "port": 465,
    "secure": true,
    "auth": {
        "user": "user",
        "pass": "pass"
    }
}
```

### Local Mail Delivery
If you're using Postfix, Sendmail, or an equivalent MTA locally, your `config/email.json`will look something like the following: 

```json
{
    "host": "localhost",
    "port": 25,
    "secure": false,
    "auth": {
        "user": "",
        "pass": ""
    }
}
```

15. The following configuration files are generated and updated by the kvkit application. They should never be edited manually:

- `config/forms.json` Web form configurations. 
- `config/hosts.json` Splunk environment configurations for remote jobs.
- `config/jobs.json` Scheduled remote jobs.

## Start kvkit

16. Start kvkit. See the [pm2 documentation](https://www.npmjs.com/package/pm2) for available options and configurations.

```bash
pm2 start kvkit
```

## Login to kvkit

17. Access kvkit using the configuration from step 12. https://`addr`:`port` (i.e., https://10.5.5.5:8008). Login with any Splunk account that is associated with the kvkit\_admin role from step 3. Please note that kvkit, by design, does not have any local users. It relies on Splunk for everything.

If the installation and configuration worked properly, you should now see a list of your KV stores and collections. 

## Configure your first form
Our [Web Forms on Splunk with kvkit](https://www.youtube.com/watch?v=PD4oLOrNqYQ) video steps through 18 - 21 below. You might want to check it out if you haven't already. 

18. Click on the collection that you would like to work with. If the collection has records, you will see them on the *View* page. You can search and sort data in the table view. You can also edit or delete individual records.

19. Click on *Form Config* and define your form fields' configuration, sharing preferences, visual design (template), and redirect.

20. Click *Save Configuration* to apply your changes.

## Access the form

21. Once the form is configured you can access it via the *Form* link. If the form is set to 'Restricted', you will be redirected to the login page. This will occur even if you are a kvkit admin already authenticated to the app.

## Access form contents

22. If you shared the form data, a read-only copy of the data will be accessible via the URL shown in *Config*. There is currently no option to restrict access to the collected form data since it can be presented more effectively within Splunk.

## Drill-downs
 
23. When sharing a kvkit form with your Splunk users, it may be helpful to pass Splunk token values to populate certain form fields. To illustrate consider an example table in which you want the:

* the kvkit source\_ip\_addr form field to populate with the value of $row.src\_ip$ 
* the dest\_ip\_addr form field to populate with the value of $row.dest\_ip$
* the src\_username field to populate with the value of the global $env:user$ token

Your drill-down would need to point to: 

```html
https://KVKIT_SERVER:8008/form/APP_NAME/KVSTORE_COLLECTION?drilldown&source_ip_addr=$row.src_ip$&dest_ip_addr=$row.dest_ip$&src_username=$env:user$
```

So 'fighters' collection in the 'foo' app on the 'kvkit.everlo.ng' server would look like this: 

```html
https://kvkit.everlo.ng:8008/form/foo/fighters?drilldown&source_ip_addr=$row.src_ip$&dest_ip_addr=$row.dest_ip$&src_username=$env:user$
```

## Weeping? Gnashing of teeth? 

Please post any issues to [https://github.com/fancherblack/kvkit/issues](https://github.com/fancherblack/kvkit/issues).  

## Credits and thanks

- Backend development by Joshua Benfield (@devhsoj)
- Technical strategy and frontend development by Jay Benfield (@jaybenfield) 
- Significant contributions to the concept and testing of early versions by Casey Pike. Casey, if you're reading this, get me your GitHub username for proper README linkage. :-)  

**Happy CRUD-ing!**

