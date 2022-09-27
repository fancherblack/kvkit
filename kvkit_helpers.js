const HttpsProxyAgent = require('https-proxy-agent');
const {createHash,randomBytes} = require('crypto');
const cron = require('node-cron');
const https = require('https');
const _ = require('lodash');
const fs = require('fs');
const ip = require('ip');

// Required for self signed certificates that Splunk uses, can remove if Splunk certificates are signed
// NOTE: Still Secure! All requests are still used with HTTPS & TLS
process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

var kvkit = {
    ssl:{},
    jobs:{},
    apps:{},
    hosts:[],
    forms:{},
    email:{},
    config:{},
    splunk:{},
    server:{},
    credentials:{},
    async get({hostname,port,path,auth}) {// A handy function used frequently to easily handle Splunk GET requests
        let options = {
            hostname:hostname ? hostname : this.splunk.hostname,
            port:port ? port : this.splunk.rest_port,
            path,
            headers:{
                Authorization:auth ? auth : 'Basic ' + new Buffer.from(`${this.credentials.username}:${this.credentials.password}`,'ascii').toString('base64')
            }
        };

        this.server.proxy ? options.hostname === 'riza.redfactorapps.com' ? options.agent = new HttpsProxyAgent(this.server.proxy) : false : false;

        return new Promise((resolve,reject) => {
            let data = '';
    
            https.get(options,res => {
                if(res.statusCode !== 200 && res.statusCode !== 201) resolve(res.statusCode);
    
                res.setEncoding('utf8');
                res.on('data',chunk => data += chunk);
                res.on('end',() => resolve(data));
                res.on('error',err => reject(err));
            }).on('error',err => {console.log(`Failed to connect to ${hostname}:${port}`);reject(`Failed to connect to ${hostname}:${port}`)});
        });
    },
    post({hostname,port,path,auth,contentType,data}) {// A handy function used frequently to easily handle Splunk POST requests
        let options = {
            hostname:hostname ? hostname : this.splunk.hostname,
            port:port ? port : this.splunk.rest_port,
            method:'POST',
            path,
            headers:{
                Authorization:auth ? auth : 'Basic ' + new Buffer.from(`${this.credentials.username}:${this.credentials.password}`,'ascii').toString('base64'),
                'Content-Type':contentType,
                'Content-Length':Buffer.byteLength(data)
            }
        };

        this.server.proxy ? options.hostname === 'riza.redfactorapps.com' ? options.agent = new HttpsProxyAgent(this.server.proxy) : false : false;
    
        return new Promise((resolve,reject) => {
            try {
                let req = https.request(options,res => resolve(res));
    
                req.write(data);
                req.end();
            } catch(err) {
                reject(err);
            }
        });
    },
    delete({hostname,port,path,auth}) {// A handy function used frequently to easily handle Splunk DELETE requests
        let options = {
            hostname:hostname ? hostname : this.splunk.hostname,
            port:port ? port : this.splunk.rest_port,
            method:'DELETE',
            path,
            headers:{
                Authorization:auth ? auth : 'Basic ' + new Buffer.from(`${this.credentials.username}:${this.credentials.password}`,'ascii').toString('base64'),
            }
        };
    
        this.server.proxy ? options.hostname === 'riza.redfactorapps.com' ? options.agent = new HttpsProxyAgent(this.server.proxy) : false : false;

        return new Promise((resolve,reject) => {
            try {
                let req = https.request(options,res => resolve(res));
                req.end();
            } catch(err) {
                reject(err);
            }
        });
    },
    readJson(filename) { // Asynchronously reads json files
        return new Promise((resolve,reject) => {
            fs.readFile(filename,(err,data) => {
                if(err) resolve({});
                else resolve(JSON.parse(data));
            });
        });
    },
    log(data,sourcetype='this_audit') {// A function used to log data to a Splunk HEC 
        let log_data = JSON.stringify({
            event:data,
            sourcetype:sourcetype
        });
        
        this.post({
            hostname:this.splunk.logging_hostname,
            port:this.splunk.hec_port,
            path:'/services/collector',
            contentType:'application/json',
            data:log_data,
            auth:`Splunk ${this.credentials.hecToken}`
        });
    },
    async updateApps({hostname,port,auth}) {// Updates apps and kv stores, by parsing data given by splunk
        this.server = await this.readJson(__dirname + '/config/server.json');
        this.splunk = await this.readJson(__dirname + '/config/splunk.json');
    
        let initial_resp = JSON.parse(await this.get({hostname,port,auth,path:'/servicesNS/nobody/-/storage/collections/config?output_mode=json'}));
        let paging = initial_resp.paging;
        let pages = Math.ceil(paging.total/paging.perPage);
        let apps = {};

        for(let o=0; o<pages*paging.perPage; o+=paging.perPage) {
            let json = JSON.parse(await this.get({hostname,port,auth,path:`/servicesNS/nobody/-/storage/collections/config?output_mode=json&offset=${o}`}));

            if(json !== undefined && json.entry !== undefined) {
                for(let entry of json.entry) {
                    let app = entry.acl.app,
                        collection = entry.name,
                        disabled = entry.content.disabled,
                        raw_fields = entry.content,
                        fields = [];
                    
                    for(let field in raw_fields) {;
                        if(field.includes('field.')) {
                            fields.push(field.replace('field.',''));
                        }
                    }
    
                    if(disabled === false && !this.config.excluded_apps.includes(app) && !this.config.excluded_kvstores.includes(collection)) {
                        if(!apps[app]) apps[app] = {};
    
                        apps[app][collection] = {
                            fields,
                            data:''
                        }
                    }
                }
            }
        }

        return apps
    },
    async updateData({hostname,port,auth,app,collection,apps}) {// Updates apps variable with Splunk given data
        let data = JSON.parse(await this.get({hostname,port,auth,path:`/servicesNS/nobody/${app}/storage/collections/data/${collection}`}));

        for(let chunk of data) {
            for(let key in chunk) {
                if(!apps) {
                    if(!this.apps[app][collection].fields.includes(key) && key !== '_key') {
                        delete chunk[key];
                    }
                }
            }
        }
    
        return data
    },
    async getUserRoles(username) {// Returns a list of splunk roles a specified user has
        return await new Promise(async (resolve,reject) => {
            let json = JSON.parse(await this.get({path:`/services/authentication/users/${username}?output_mode=json`}));

            if(json.entry !== undefined) resolve(json.entry[0].content.roles);
            else resolve([]);
        })
    },
    async getRoles() {// Returns all roles in your Splunk instance
        let json = JSON.parse(await this.get({path:'/services/authorization/roles?output_mode=json'}));
        let roles = [];
    
        if(json.entry !== undefined) {
            for(let role of json.entry) {
                roles.push(role.name);
            };
        };
    
        for(let excluded_role of this.config.excluded_roles) {
            let index = roles.indexOf(excluded_role);
            // If a role is in the config.excluded_roles, then remove it...
            if(index !== -1) roles.splice(index,1);
        }
    
        return roles;
    },
    async load() {// Loads all needed config files to start the app
        return await new Promise(async (resolve,reject) => {
            // Config used for the HTTPS/SSL Options 
            this.ssl = await this.readJson(__dirname + '/config/ssl.json');
            // Config used for the REST account that makes all the requests for Splunk
            this.credentials = await this.readJson(__dirname + '/config/credentials.json');
            // Config used for the server & proxy information
            this.server = await this.readJson(__dirname + '/config/server.json');
            // Config used for Splunk information
            this.splunk = await this.readJson(__dirname + '/config/splunk.json');
            // Config Used for the all the forms' configuration
            this.forms = await this.readJson(__dirname + '/config/forms.json');
            // Config used for how the app runs
            this.config = await this.readJson(__dirname + '/config/app.json');
            // Config used for email lists & sending
            this.email = await this.readJson(__dirname + '/config/email.json');
            // File for storing orchestration hosts
            this.hosts = await this.readJson(__dirname + '/config/hosts.json');
            // File for storing orchestration jobs
            this.jobs = await this.readJson(__dirname + '/config/jobs.json');

            for(let job in this.jobs) {
                if(this.jobs[job].type === 'orchestration') {
                    this.jobs[job].cron = cron.schedule(this.jobs[job].format,async () => {
                        let options = this.jobs[job].options;
                        let split_names = options.src.split('-');
                
                        let hostname = split_names[0];
                        let app = split_names[1];
                        let collection = split_names[2];
                        let srcHost = this.hosts.filter(h => {return h.hostname === hostname})[0];
                        let data = await this.updateData({hostname:srcHost.hostname,port:srcHost.port,app,collection,apps:srcHost.apps});
                        
                        if(options.action === 'merge' || options.action === 'append' || options.action === 'overwrite') {
                            for(let dst of options.dst) {
                                if(dst) {
                                    split_names = dst.split('-');
                
                                    let dstHostname = split_names[0];
                                    let dstApp = split_names[1];
                                    let dstCollection = split_names[2];
                                    let dstHost = this.hosts.filter(h => {return h.hostname === dstHostname})[0];
                        
                                    if(options.action === 'overwrite') await this.delete({path:`/servicesNS/nobody/${dstApp}/storage/collections/data/${dstCollection}`})
                
                                    for(let row of data) {
                                        if(!options.keepKey) delete row._key;
                
                                        this.post({
                                            hostname:dstHost.hostname,
                                            port:dstHost.port,
                                            auth:'Basic ' + new Buffer.from(`${dstHost.username}:${dstHost.password}`,'ascii').toString('base64'),
                                            path:`/servicesNS/nobody/${dstApp}/storage/collections/data/${dstCollection}`,
                                            contentType:'application/json',
                                            data:JSON.stringify(row)
                                        })
                                        .catch(err => {
                                            console.log(err);
                                            res.status(500).send('Server Error.');
                                        });
                                    }
                                }
                            }
                        }
                    });
                } else if(this.jobs[job].type === 'collection-backup') {
                    this.jobs[job].cron = cron.schedule(this.jobs[job].backup_schedule,async () => {
                        kvkit.apps[this.jobs[job].app][this.jobs[job].collection].data = await kvkit.updateData({hostname:kvkit.splunk.hostname,port:kvkit.splunk.rest_port,app:this.jobs[job].app,collection:this.jobs[job].collection});
        
                        // Checks if a backup directory exists, creates a directory if not, then writes a backup
                        let csv = kvkit.csv(this.jobs[job].app,this.jobs[job].collection);
                        let exists = fs.existsSync(`${__dirname}/backups/${this.jobs[job].app}`);
        
                        if(!exists) {
                            fs.mkdirSync(`${__dirname}/backups/${this.jobs[job].app}`);
                            fs.mkdirSync(`${__dirname}/backups/${this.jobs[job].app}/${this.jobs[job].collection}`);
                        }
        
                        fs.writeFileSync(`${__dirname}/backups/${this.jobs[job].app}/${this.jobs[job].collection}/${this.jobs[job].collection}-${this.jobs[job].username}-${new Date().getTime()}.csv`,csv);
                    });
                }

                this.jobs[job].cron.start();
            }

            this.apps = await this.updateApps({hostname:this.splunk.hostname,port:this.splunk.rest_port});
            resolve(true);
        });
    },
    csv(app,collection) {
        let data = Object.assign({},this.apps[app][collection]);
        let csv = data.fields.join(',') + '\n';

        for(let chunk of data.data) {
            delete chunk._key;
            csv += `${Object.values(chunk).join(',')}\n`;
        }

        return csv
    },
    randomString(length) {
        return randomBytes(length/2).toString('hex');
    },
    hash(string,type='sha512') {
        let hash = createHash(type);
        hash.update(string);
        return hash.digest('hex');
    },
    getInstanceHash() {
        return this.hash(__dirname + '---' + ip.address());
    },
    saveJobs() {
        let safeJobs = _.cloneDeep(this.jobs);

        for(let job in safeJobs) {
            safeJobs[job].cron = null;
        }

        fs.writeFileSync(__dirname + '/config/jobs.json',JSON.stringify(safeJobs,null,4));
    }
};

module.exports = kvkit;