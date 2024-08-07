const es6Renderer = require('express-es6-template-engine');
const querystring = require('querystring');
const session = require('express-session');
const kvkit = require('./kvkit_helpers');
const express = require('express');
const cron = require('node-cron');
const https = require('https');
const cors = require('cors');
const fs = require('fs');

// Required for self signed certificates that Splunk uses, can remove if Splunk certificates signed
// NOTE: Still Secure! All requests are still used with HTTPS & TLS
process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;

// Reads cert & key files to start app with HTTPS
var transporter = {};
var app = express();

// Here we use express urlencoded to easily read from the submitted forms.
// And here we initialized an express session with a secure,random, secret key

app.use(express.urlencoded({extended:true}));
app.use(session({
    secret:kvkit.randomString(1024),
    resave:false,
    saveUninitialized:false
}));

// Here we use the es6Renderer library to render server-side variables to each view in the views/ directory
// NOTE: Each variable is contained and only certain variables are able to be seen, Example: app_name kv_name
// ALSO NOTE: The user will not see the variable name or any es6 script to show the variable, they will only see the variable's value

app.engine('html',es6Renderer);
app.set('views',__dirname + '/views');
app.set('view engine','html');

// Allow cross origin access to the app, so people may use it in splunk
app.use(cors());

// Below are routes to serve different static files in an organized fashion 

app.use('/static/',express.static(__dirname + '/views/static'));
app.use('/bootstrap/',express.static(__dirname + '/node_modules/bootstrap/dist'));
app.use('/fa/',express.static(__dirname + '/node_modules/@fortawesome/fontawesome-free'));
app.use('/jquery/',express.static(__dirname + '/node_modules/jquery/dist'));
app.use('/datatables/',express.static(__dirname + '/node_modules/datatables.net'));
app.use('/datatables-dt/',express.static(__dirname + '/node_modules/datatables.net-dt'));
app.use('/datatables-bs4/',express.static(__dirname + '/node_modules/datatables.net-bs4'));

// The view for the login page /views/Login.html

app.get('/admin/login',(req,res) => {
    if(!req.session.active) res.render('Login'); 
    else res.redirect('/');
});

// Below is how an admin would login
// NOTE: The user must be able to authenticate with Splunk, and also have the 'kvkit_admin' role to access the app
// ALSO NOTE: completely separate from the form login

app.post('/admin/login',(req,res) => {
    kvkit.post({
        path:'/services/auth/login',
        contentType:'application/x-www-form-urlencoded',
        data:querystring.stringify(req.body)
    }).then(async auth_res => {
        // Checks if the user can even log into Splunk, and then checks if they have the 'kvkit_admin' role
        if(auth_res.statusCode === 200) {
            let roles = await kvkit.getUserRoles(req.body.username);

            if(roles.includes('kvkit_admin')) {
                kvkit.log({
                    eventType:'Successful Admin Login',
                    username:req.body.username,
                    ip_addr:req.ip,
                    timestamp:new Date().toLocaleString()
                });

                req.session.active = true;
                req.session.username = req.body.username;
                return res.redirect('/');
            }
        }

        kvkit.log({
            eventType:'Unsuccessful Login',
            username:req.body.username,
            ip_addr:req.ip,
            timestamp:new Date().toLocaleString()
        });

        res.render('FailedLogin');
    });
});

// The view for the login page /views/Login.html

app.get('/admin/logout',(req,res) => {
    if(req.session.active) {
        req.session.active = false;
        res.redirect('/admin/login');
    } else res.redirect('/admin/login');
});

// The view for the form login page /views/FormLogin.html

app.get('/form/login',(req,res) => {
    if(!req.session.formLoggedIn) res.render('FormLogin');
    else res.redirect('/');
});

// Below is how a user would login to access the specified form
// NOTE: User must be a splunk user, and if the form is configured as private, then they need to have at least one role in the allowed_roles option to access it
// ALSO NOTE: Completely separate from the admin login page

app.post('/form/login',(req,res) => {
    kvkit.post({
        path:'/services/auth/login',
        contentType:'application/x-www-form-urlencoded',
        data:querystring.stringify(req.body)
    }).then(async auth_res => {
        if(auth_res.statusCode === 200) {
            if(req.session.formPath === undefined) return res.send('You are trying to access a form in an illegal way.');

            kvkit.forms = await kvkit.readJson(__dirname + '/config/forms.json');

            let form_sharing = kvkit.forms[req.session.formPath.app][req.session.formPath.kvstore].sharing;
            let allowed_roles = form_sharing.roles;
            let user_roles = await kvkit.getUserRoles(req.body.username);
            
            if(!Array.isArray(allowed_roles)) allowed_roles = allowed_roles.split(','); 

            if(form_sharing.public) {
                req.session.formLoggedIn = true;
                res.redirect(req.session.formPath.url);
            } else if(form_sharing.private) {
                let valid = false;

                for(let role of allowed_roles) {
                    if(user_roles.includes(role)) {
                        valid = true;
                        break
                    }
                }

                if(valid) {
                    kvkit.log({
                        eventType:'Successful Form Login',
                        username:req.body.username,
                        ip_addr:req.ip,
                        timestamp:new Date().toLocaleString()
                    });

                    req.session.formLoggedIn = true;
                    req.session.formUsername = req.body.username;
                    req.session.auth = 'Basic ' + new Buffer.from(`${req.body.username}:${req.body.password}`,'ascii').toString('base64');
                    res.redirect(req.session.formPath.url);
                } else {
                    kvkit.log({
                        eventType:'Unsuccessful Form Login',
                        username:req.body.username,
                        ip_addr:req.ip,
                        timestamp:new Date().toLocaleString()
                    });
                    
                    res.render('FailedLogin');
                }
            } else {
                kvkit.log({
                    eventType:'Unsuccessful Form Login',
                    username:req.body.username,
                    ip_addr:req.ip,
                    timestamp:new Date().toLocaleString()
                });

                res.render('FailedLogin');
            }
        } else res.status(auth_res.statusCode).render('FailedLogin');
    });
});

// The app config page for the main app /views/AppConfig.html

app.get('/admin/config',(req,res) => {
    if(req.session.active) {
        res.render('AppConfig',{locals:{
            config:kvkit.config,
            credentials:kvkit.credentials,
            splunk:kvkit.splunk,
            email:kvkit.email,
            username:req.session.username
        }});
    } else res.redirect('/admin/login');
});

// Posts & writes the data from the app config page for the main app

app.post('/admin/config',async (req,res) => {
    if(req.session.active) {
        kvkit.credentials.username = req.body.username;
        kvkit.credentials.password = req.body.password;

        kvkit.splunk.hostname = req.body.hostname;
        kvkit.splunk.rest_port = parseInt(req.body.rest_port);
        kvkit.splunk.hec_port = parseInt(req.body.hec_port);

        kvkit.config.excluded_roles = req.body.excluded_roles.split(',');
        kvkit.config.excluded_apps = req.body.excluded_apps.split(',');
        kvkit.config.excluded_kvstores = req.body.excluded_kvstores.split(',');
        kvkit.config.max_search_time = parseInt(req.body.max_search_time);

        kvkit.email.host = req.body.email_host;
        kvkit.email.port = req.body.email_port;
        kvkit.email.secure = (req.body.email_secure === 'on');
        kvkit.email.auth = {
            user:req.body.email_user,
            pass:req.body.email_pass
        };

        fs.writeFileSync(__dirname + '/config/credentials.json',JSON.stringify(kvkit.credentials,null,4));
        fs.writeFileSync(__dirname + '/config/splunk.json',JSON.stringify(kvkit.splunk,null,4));
        fs.writeFileSync(__dirname + '/config/email.json',JSON.stringify(kvkit.email,null,4));
        fs.writeFileSync(__dirname + '/config/app.json',JSON.stringify(kvkit.config,null,4));

        kvkit.apps = await kvkit.updateApps({hostname:kvkit.splunk.hostname,port:kvkit.splunk.rest_port});

        res.redirect('/');
    } else res.redirect('/admin/login');
});

// The main page for the kvkit app /views/AppHome.html

app.get('/',async (req,res) => {
    if(req.session.active) {
       kvkit.apps = await kvkit.updateApps({hostname:kvkit.splunk.hostname,port:kvkit.splunk.rest_port});

        res.render('AppHome',{locals:{
            apps:kvkit.apps,
            username:req.session.username
        }});
    } else res.redirect('/admin/login');
});

// The view for the collection page /views/Collection.html

app.get('/app/:app/:kvstore',async (req,res) => {
    if(req.session.active) {
        try {
            kvkit.apps[req.params.app][req.params.kvstore].data = await kvkit.updateData({hostname:kvkit.splunk.hostname,port:kvkit.splunk.rest_port,app:req.params.app,collection:req.params.kvstore});

            res.render('Collection',{locals:{
                app_name:req.params.app,
                kv_name:req.params.kvstore,
                data:kvkit.apps[req.params.app][req.params.kvstore],
                username:req.session.username
            }});
        } catch {
            res.status(404).render('NotFound');
        }
    } else res.redirect('/admin/login');
});

// The view for the operations page /views/Operations.html

app.get('/operations/:app/:kvstore',async (req,res) => {
    if(req.session.active) {
        let backups = (await new Promise((resolve,reject) => {
            fs.readdir(`${__dirname}/backups/${req.params.app}/${req.params.kvstore}`,(err,files) => {
                if(err) resolve([]);
                else resolve(files);
            });
        })).filter(val => {return val.includes(req.params.kvstore)});

        let backupData = {}
        for(let backup of backups) {
            let data = fs.readFileSync(`${__dirname}/backups/${req.params.app}/${req.params.kvstore}/${backup}`);

            backupData[backup] = {
                user:backup.split('-').length === 3 ? backup.split('-')[1] : 'unknown',
                timestamp:backup.split('-').length === 3 ? new Date(parseInt(backup.split('-')[2].replace('.csv',''))) : 'unknown',
                filesize:data.byteLength,
                records:data.toString().split('\n').length-2
            }
        }
        
        res.render('Operations',{locals:{
            app_name:req.params.app,
            kv_name:req.params.kvstore,
            username:req.session.username,
            backupData,
            jobs:kvkit.jobs
        }});
    } else res.redirect('/admin/login');
});

// Sets the backup schedule in CRON format for specified kvstore

app.post('/operations/:app/:kvstore',(req,res) => {
    if(req.session.active) {
        let app = req.params.app;
        let kvstore = req.params.kvstore;
        let backup_schedule = req.body.backup_schedule;


        if(!kvkit.jobs[`${app}-${kvstore}`]) {
            kvkit.jobs[`${app}-${kvstore}`] = {
                type:'collection-backup',
                app,
                collection,
                backup_schedule,
                username:req.session.username,
                cron:null
            }
        }

        if(backup_schedule === 'CLEAR') {
            if(kvkit.jobs[`${app}-${kvstore}`]) {
                if(kvkit.jobs[`${app}-${kvstore}`].cron) {
                    console.log('test')
                    kvkit.jobs[`${app}-${kvstore}`].cron.destroy();
                    kvkit.jobs[`${app}-${kvstore}`].cron.backup_schedule = '';
                }
            }

            res.status(200).redirect(`/operations/${app}/${kvstore}`);
            return;
        }

        if(backup_schedule.length !== 0 && cron.validate(backup_schedule)) {
            if(kvkit.jobs[`${app}-${kvstore}`].cron) kvkit.jobs[`${app}-${kvstore}`].cron.destroy();

            kvkit.jobs[`${app}-${kvstore}`].cron = cron.schedule(backup_schedule,async () => {
                kvkit.apps[app][kvstore].data = await kvkit.updateData({hostname:kvkit.splunk.hostname,port:kvkit.splunk.rest_port,app:req.params.app,collection:req.params.kvstore});

                // Checks if a backup directory exists, creates a directory if not, then writes a backup
                let csv = kvkit.csv(app,kvstore);
                let exists = fs.existsSync(`${__dirname}/backups/${app}`);

                if(!exists) {
                    fs.mkdirSync(`${__dirname}/backups/${app}`);
                    fs.mkdirSync(`${__dirname}/backups/${app}/${kvstore}`);
                }

                fs.writeFileSync(`${__dirname}/backups/${app}/${kvstore}/${kvstore}-${req.session.username}-${new Date().getTime()}.csv`,csv);
            });

            kvkit.jobs[`${app}-${kvstore}`].cron.start();
            kvkit.saveJobs();

            kvkit.log({
                eventType:'Backup Schedule Created',
                username:req.session.username,
                app,
                kvstore,
                cron_format:backup_schedule,
                ip_addr:req.ip,
                timestamp:new Date().toLocaleString()
            });
        } else return res.status(409).send('Invalid Cron Format');

        res.status(200).redirect(`/operations/${req.params.app}/${req.params.kvstore}`);
    } else res.redirect('/admin/login');
});

app.get('/public/app/:app/:kvstore',async (req,res) => {
    try {
        kvkit.forms = await kvkit.readJson(__dirname + '/config/forms.json');

        if(kvkit.forms[req.params.app][req.params.kvstore].sharing.public_view) {
            kvkit.apps[req.params.app][req.params.kvstore].data = await kvkit.updateData({hostname:kvkit.splunk.hostname,port:kvkit.splunk.rest_port,app:req.params.app,collection:req.params.kvstore});

            res.render('PublicCollection',{locals:{
                app_name:req.params.app,
                kv_name:req.params.kvstore,
                data:kvkit.apps[req.params.app][req.params.kvstore]
            }});
        } else res.status(404).send('Public view not enabled.');
    } catch {
        res.status(404).render('NotFound');
    }
});

// The view for the edit page /views/Edit.html

app.get('/update/:app/:kvstore/:key',async (req,res) => {
    if(req.session.active) { 
        if(kvkit.forms[req.params.app]) {
            for(let conf in kvkit.forms[req.params.app][req.params.kvstore]) {
                if(conf !== 'sharing') {
                    if(kvkit.forms[req.params.app][req.params.kvstore][conf].values.includes('search: ')) {
                        await new Promise((resolve,reject) => {
                            let search = kvkit.forms[req.params.app][req.params.kvstore][conf].values.split('search: ')[1];
                            if(search[0] !== '|') search = 'search ' + search;

                            kvkit.post({
                                path:'/services/search/jobs?output_mode=json',
                                contentType:'x-www-form-urlencoded',
                                data:querystring.stringify({search}),
                                auth:req.session.auth ? req.session.auth : 'Basic ' + new Buffer.from(`${kvkit.credentials.username}:${kvkit.credentials.password}`,'ascii').toString('base64')
                            }).then(async search_res => {
                                let sid = JSON.parse(await new Promise((resolve,reject) => {
                                    let data = '';
                    
                                    search_res.on('data',chunk => data += chunk);
                                    search_res.on('end',() => resolve(data));
                                    search_res.on('error',err => reject(err));
                                })).sid;
    
                                kvkit.log({
                                    eventType:'New Search',
                                    username:req.session.username,
                                    search:kvkit.forms[req.params.app][req.params.kvstore][conf].values.split('search: ')[1],
                                    sid,
                                    ip_addr:req.ip,
                                    timestamp:new Date().toLocaleString()
                                });
    
                                let start = new Date();
                                let results = sid ? await kvkit.get({path:`https://localhost:8089/services/search/jobs/${sid}/results/?output_mode=json`}) : 204;

                                while(results === 204) {
                                    results = await kvkit.get({path:`https://localhost:8089/services/search/jobs/${sid}/results/?output_mode=json`});

                                    let elapsed = Math.floor((new Date() - start)/1000);
    
                                    if(elapsed > kvkit.config.max_search_time) {
                                        results = 408;
                                        break;
                                    }
                                }
                                
                                if(results === 401 || results === 404 || results === 400) kvkit.forms[req.params.app][req.params.kvstore][conf].values = 'Error loading from Splunk Search...';
                                else if(results === 408) kvkit.forms[req.params.app][req.params.kvstore][conf].values = 'Search took too long...'
                                else {
                                    let field = kvkit.forms[req.params.app][req.params.kvstore][conf];
                                    let parsed_results = [];

                                    results = JSON.parse(results);

                                    if(field.type === 'checkbox' || field.type === 'radio' || field.type === 'dropdown' || field.type === 'multiselect') parsed_results = results.results;
                                    else {
                                        for(let result of results.results) {
                                            delete result['_tc'];
                                            parsed_results.push(Object.values(result).join(', '));
                                        }

                                        parsed_results = parsed_results.join('|');
                                    }

                                    kvkit.forms[req.params.app][req.params.kvstore][conf].values = parsed_results;
                                }

                                resolve(true);
                            });
                        });
                    }
                }
            }
        }

        res.render('Edit',{locals:{
            app_name:req.params.app,
            kv_name:req.params.kvstore,
            config:kvkit.forms[req.params.app][req.params.kvstore],
            key:req.params.key,
            username:req.session.username
        }});
    } else res.redirect('/admin/login');
});

// Returns data by key from specified splunk kv store

app.get('/key/:app/:kvstore/:key',async (req,res) => {
    if(req.session.active) {
        let data = await kvkit.get({path:`/servicesNS/nobody/${req.params.app}/storage/collections/data/${req.params.kvstore}/${req.params.key}`});
        res.send(data);
    } else res.redirect('/admin/login');
});

// Set data by key from the Edit page

app.post('/key/:app/:kvstore/:key',async (req,res) => {
    if(req.session.active) {
        let prevData = await kvkit.get({path:`/servicesNS/nobody/${req.params.app}/storage/collections/data/${req.params.kvstore}/${req.params.key}`});
        delete prevData['_key'];
        delete prevData['_user'];

        let data = JSON.parse(await new Promise((resolve,reject) => {
            let data = '';
    
            req.on('data',chunk => data += chunk);
            req.on('end',() => resolve(data));
            req.on('error',(err) => reject(err));
        }).catch(err => console.log(err)));

        for(let val in data) {
            if(data[val] instanceof Object) data[val] = data[val].join(form_config.sharing.data_delimiter ? form_config.sharing.data_delimiter : ',');
            data[val] = data[val].replace(/\</g,'&lt;').replace(/\>/g,'&gt;'); // Prevents XSS inside the web app
        }

        kvkit.post({
            path:`/servicesNS/nobody/${req.params.app}/storage/collections/data/${req.params.kvstore}/${req.params.key}`,
            contentType:'application/json',
            data:JSON.stringify(data)
        });

        kvkit.log({
            eventType:'Data Update',
            username:req.session.username,
            key:req.params.key,
            prevData,
            data:JSON.stringify(data),
            ip_addr:req.ip,
            timestamp:new Date().toLocaleString()
        });

        res.redirect(`/app/${req.params.app}/${req.params.kvstore}`)
    } else res.redirect('/admin/login');
})

// Delete data by key from the Collection page

app.post('/remove/:app/:kvstore/:key',async (req,res) => {
    if(req.session.active) {
        kvkit.delete({path:`/servicesNS/nobody/${req.params.app}/storage/collections/data/${req.params.kvstore}/${req.params.key}`})
        .then(delete_res => {
            kvkit.log({
                eventType:'Data Deletion',
                username:req.session.username,
                key:req.params.key,
                ip_addr:req.ip,
                timestamp:new Date().toLocaleString()
            });

            res.status(delete_res.statusCode).send('Deleted.');
        })
        .catch(err => res.status(500).send(err));
    } else res.redirect('/admin/login');
});

// The view for the config page /views/Config.html

app.get('/edit/config/:app/:kvstore',async (req,res) => {
    if(req.session.active) {
        kvkit.forms = await kvkit.readJson(__dirname + '/config/forms.json');

        let form_templates = await new Promise((resolve,reject) => {
            fs.readdir(__dirname + '/views/custom/',(err,files) => {
                if(err) {
                    console.log(err);
                    resolve([]);
                }
                else {
                    let i = files.indexOf('submitted');
                    if(i !== -1) files.splice(i,1);
                    resolve(files);
                }
            })
        });

        let submission_templates = await new Promise((resolve,reject) => {
            fs.readdir(__dirname + '/views/custom/submitted/',(err,files) => {
                if(err) {
                    console.log(err);
                    resolve([]);
                }
                else resolve(files);
            })
        });

        res.render('Config',{locals:{
            app_name:req.params.app,
            kv_name:req.params.kvstore,
            fields:kvkit.apps[req.params.app][req.params.kvstore].fields,
            config:kvkit.forms[req.params.app] ? kvkit.forms[req.params.app][req.params.kvstore] : undefined,
            roles:await kvkit.getRoles(),
            username:req.session.username,
            site:req.header('Host'),
            form_templates,
            submission_templates
        }});
    } else res.redirect('/admin/login');
});

// Reads given config from the app, and writes it to conf/forms.json so it could be read from forms and changed

app.post('/:app/:kvstore/setConfig',async (req,res) => {
    if(req.session.active) {
        kvkit.forms = await kvkit.readJson(__dirname + '/config/forms.json');
        // Default config so that if no values are specified, there will be no errors
        // if(req.body.config) {
        //     if(!Object.keys(kvkit.forms).includes(req.params.app)) kvkit.forms[req.params.app] = {}
        //     kvkit.forms[req.params.app][req.params.kvstore] = JSON.parse(req.body.config);

        //     fs.writeFileSync(__dirname + '/config/forms.json',JSON.stringify(kvkit.forms,null,4));
        //     return res.sendStatus(200);
        // }

        let config = {
            sharing:{
                public:false,
                private:false,
                public_data_view:false,
                private_data_view:false,
                splunk_search_user_auth:false,
                public_form_template:'',
                private_form_template:'',
                roles:[],
                post_process_search:'',
                email_list:'',
                email_msg:'',
                email_submitter:false,
                submitter_msg:'',
                submission_template:''
            }
        };

        // Reads each field in the collection and sets config based on what user gave it, otherwise setting a default config
        let order = 1;
        for(let item in req.body) {
            let field = item.split('.')[0];
            let name = item.split('.')[1];
            let val = req.body[item];

            if(field !== 'sharing') {
                if(!Object.keys(config).includes(field)) {
                    config[field] = {
                        order,
                        form_name:field,
                        description:'',
                        static:false,
                        hidden:false,
                        required:false,
                        type:'input',
                        values:''
                    };
                }

                if(!isNaN(val) && val.length !== 0) val = parseInt(val);

                if(name !== 'form_name') {
                    if(req.body[`${field}.required`] === undefined) config[field].required = false;
                    else if(req.body[`${field}.required`] === 'on') config[field].required = true;
    
                    if(req.body[`${field}.static`] === undefined) config[field].static = false;
                    else if(req.body[`${field}.static`] === 'on') config[field].static = true;

                    if(req.body[`${field}.hidden`] === undefined) config[field].hidden = false;
                    else if(req.body[`${field}.hidden`] === 'on') config[field].hidden = true;

                    if(val === 'on') val = true;
                    else if(val === 'off') val = false;
    
                    config[field][name] = val;
                } else {
                    if(val !== '') config[field][name] = val
                    else config[field][name] = field;
                }

                if(name == 'values') config[field][name] = config[field][name].toString();
            } else {
                if(val === 'on') val = true;
                else if(val === 'off') val = false;

                if(val === 'Choose a Template') val = '';

                config.sharing[name] = val; 
            }
        }

        if(!Object.keys(kvkit.forms).includes(req.params.app)) kvkit.forms[req.params.app] = {}
        kvkit.forms[req.params.app][req.params.kvstore] = config;

        fs.writeFileSync(__dirname + '/config/forms.json',JSON.stringify(kvkit.forms,null,4));

        kvkit.log({
            eventType:'KV Config Set',
            username:req.session.username,
            config:config,
            ip_addr:req.ip,
            timestamp:new Date().toLocaleString()
        });

        res.redirect(`/edit/config/${req.params.app}/${req.params.kvstore}`);
    } else res.redirect('/admin/login');
});

// The view for the user-specified form /views/Form.html

app.get('/form/:app/:kvstore',async (req,res) => {
    try {
        kvkit.forms = await kvkit.readJson(__dirname + '/config/forms.json');

        if(kvkit.forms[req.params.app]) {
            if(req.session.formLoggedIn || kvkit.forms[req.params.app][req.params.kvstore].sharing.public) {
                let drilldown = Object.keys(req.query).length >= 1 ? req.query : {};
                if(kvkit.forms[req.params.app]) {
                    for(let conf in kvkit.forms[req.params.app][req.params.kvstore]) {
                        if(conf !== 'sharing') {
                            if(drilldown[conf]) {
                                if(drilldown[conf].length >= 1) {
                                    kvkit.forms[req.params.app][req.params.kvstore][conf].values = drilldown[conf];
                                }
                            }
    
                            if(kvkit.forms[req.params.app][req.params.kvstore][conf].values.includes('search: ') && !Object.keys(drilldown).includes(conf)) {
                                await new Promise((resolve,reject) => {
                                    let search = kvkit.forms[req.params.app][req.params.kvstore][conf].values.split('search: ')[1];
                                    if(search[0] !== '|') search = 'search ' + search;
    
                                    for(let field in drilldown) {
                                        search = search.replace(new RegExp(`!{${field}}`,'g'),drilldown[field]);
                                    }
    
                                    kvkit.post({
                                        path:'/services/search/jobs?output_mode=json',
                                        contentType:'x-www-form-urlencoded',
                                        data:querystring.stringify({search}),
                                        auth:req.session.auth ? req.session.auth : 'Basic ' + new Buffer.from(`${kvkit.credentials.username}:${kvkit.credentials.password}`,'ascii').toString('base64')
                                    }).then(async search_res => {
                                        let sid = JSON.parse(await new Promise((resolve,reject) => {
                                            let data = '';
                            
                                            search_res.on('data',chunk => data += chunk);
                                            search_res.on('end',() => resolve(data));
                                            search_res.on('error',err => reject(err));
                                        })).sid;
            
                                        kvkit.log({
                                            eventType:'New Search',
                                            username:req.session.username,
                                            search:kvkit.forms[req.params.app][req.params.kvstore][conf].values.split('search: ')[1],
                                            sid,
                                            ip_addr:req.ip,
                                            timestamp:new Date().toLocaleString()
                                        });

                                        let start = new Date();
                                        let results = sid ? await kvkit.get({path:`https://localhost:8089/services/search/jobs/${sid}/results/?output_mode=json`}) : 204;

                                        while(results === 204) {
                                            results = await kvkit.get({path:`https://localhost:8089/services/search/jobs/${sid}/results/?output_mode=json`});

                                            let elapsed = Math.floor((new Date() - start)/1000);
            
                                            if(elapsed > kvkit.config.max_search_time) {
                                                results = 408;
                                                break;
                                            }
                                        }
                                        
                                        if(results === 401 || results === 404 || results === 400) kvkit.forms[req.params.app][req.params.kvstore][conf].values = 'Error loading from Splunk Search...';
                                        else if(results === 408) kvkit.forms[req.params.app][req.params.kvstore][conf].values = 'Search took too long...';
                                        else {
                                            let field = kvkit.forms[req.params.app][req.params.kvstore][conf];
                                            let parsed_results = [];
    
                                            results = JSON.parse(results);
    
                                            if(field.type === 'checkbox' || field.type === 'radio' || field.type === 'dropdown' || field.type === 'multiselect') parsed_results = results.results;
                                            else {
                                                for(let result of results.results) {
                                                    delete result['_tc'];
                                                    parsed_results.push(Object.values(result).join(', '));
                                                }

                                                parsed_results = parsed_results.join('|');
                                            }
                                            
                                            kvkit.forms[req.params.app][req.params.kvstore][conf].values = parsed_results;
                                        }
    
                                        resolve(true);
                                    });
                                });
                            }
                        }
                    }
                }
    
                if(kvkit.forms[req.params.app][req.params.kvstore].sharing.public) {
                    res.render((kvkit.forms[req.params.app][req.params.kvstore].sharing.public_form_template.length === 0 && kvkit.forms[req.params.app][req.params.kvstore].sharing.public_form_template !== 'Choose a Template') ? 'Form' : `custom/${kvkit.forms[req.params.app][req.params.kvstore].sharing.public_form_template}`,{locals:{
                        app_name:req.params.app,
                        kv_name:req.params.kvstore,
                        config:kvkit.forms[req.params.app][req.params.kvstore],
                        drilldown,
                        ip:req.ip
                    }});
                } else if(kvkit.forms[req.params.app][req.params.kvstore].sharing.private) {
                    res.render((kvkit.forms[req.params.app][req.params.kvstore].sharing.private_form_template.length === 0 && kvkit.forms[req.params.app][req.params.kvstore].sharing.private_form_template !== 'Choose a Template') ? 'Form' : `custom/${kvkit.forms[req.params.app][req.params.kvstore].sharing.private_form_template}`,{locals:{
                        app_name:req.params.app,
                        kv_name:req.params.kvstore,
                        config:kvkit.forms[req.params.app][req.params.kvstore],
                        drilldown,
                        ip:req.ip
                    }});
                }
            } else if(!req.session.formLoggedIn && kvkit.forms[req.params.app][req.params.kvstore].sharing.private) {
                req.session.formPath = {
                    app:req.params.app,
                    kvstore:req.params.kvstore,
                    url:req.url
                };
    
                res.redirect('/form/login');
            } else res.render('NoForm',{locals:{app_name:req.params.app,kv_name:req.params.kvstore}});
        } else res.render('NoForm',{locals:{app_name:req.params.app,kv_name:req.params.kvstore}});
    } catch(err) {
        console.log(err);
        res.render('NoForm',{locals:{app_name:req.params.app,kv_name:req.params.kvstore}});
    }
});

// Gets the data sent by the user either from the form or from the admin Add page and sends it to splunk

app.post('/:app/:kvstore/addData',async (req,res) => {
    let form_config = {};
    
    try {
        form_config = kvkit.forms[req.params.app][req.params.kvstore];
    } catch(err) {
        form_config = {sharing:false}
    }

    if(req.session.active || req.session.formLoggedIn || form_config.sharing) {        
        let data = JSON.parse(await new Promise((resolve,reject) => {
            let data = '';
    
            req.on('data',chunk => data += chunk);
            req.on('end',() => resolve(data));
            req.on('error',(err) => reject(err));
        }).catch(err => console.log(err)));

        for(let val in data) {
            if(data[val] instanceof Object) data[val] = data[val].join(form_config.sharing.data_delimiter ? form_config.sharing.data_delimiter : ',');
            data[val] = data[val].replace(/\</g,'&lt;').replace(/\>/g,'&gt;'); // Prevents XSS
        }

        kvkit.post({
            path:`/servicesNS/nobody/${req.params.app}/storage/collections/data/${req.params.kvstore}`,
            contentType:'application/json',
            data:JSON.stringify(data)
        })
        .catch(err => {
            console.log(err);
            res.status(500).send('Server Error.');
        });

        // If a post process search is defined, create the search in Splunk
        if(form_config.sharing) {
            if(form_config.sharing.post_process_search && form_config.sharing.post_process_search !== '') {
                let search = form_config.sharing.post_process_search;
    
                for(let field in data) {
                    search = search.replace(new RegExp(`!{${field}}`,'g'),data[field]);
                }
    
                if(search[0] !== '|') search = 'search ' + search;
    
                kvkit.post({
                    path:'/services/search/jobs',
                    contentType:'application/x-www-form-urlencoded',
                    data:querystring.stringify({search})
                });
            }
    
            if(form_config.sharing.email_list && form_config.sharing.email_list !== '') {
                let parsed_msg = form_config.sharing.email_msg.replace(new RegExp('!{username}','g'),req.session.username ? req.session.username : req.session.formUsername ? req.session.formUsername : 'Public User').replace(new RegExp('!{collection}','g'),req.params.kvstore).replace(new RegExp('!{app}','g'),req.params.app)
                
                for(let field in data) {
                    parsed_msg = parsed_msg.replace(new RegExp(`!{${field}}`,'g'),data[field]);
                }
                
                let subject_matching = /\[(.*?)\]/.exec(parsed_msg);

                transporter.sendMail({
                    from:kvkit.email.user,
                    to:form_config.sharing.email_list,
                    subject:subject_matching ? subject_matching.length === 2 ? subject_matching[1] : 'KvKit Submission' : 'KvKit Submission',
                    text:parsed_msg.replace(new RegExp(/\[(.*?)\]/,'g'),'')
                });
            }
    
            if(form_config.sharing.email_submitter && form_config.sharing.submitter_msg !== '' && data['email']) {
                let parsed_msg = form_config.sharing.submitter_msg.replace(new RegExp('!{username}','g'),req.session.username ? req.session.username : req.session.formUsername ? req.session.formUsername : 'Public User').replace(new RegExp('!{collection}','g'),req.params.kvstore).replace(new RegExp('!{app}','g'),req.params.app)
                
                for(let field in data) {
                    parsed_msg = parsed_msg.replace(new RegExp(`!{${field}}`,'g'),data[field]);
                }

                let subject_matching = /\[(.*?)\]/.exec(parsed_msg);
                
                transporter.sendMail({
                    from:kvkit.mail_conf.auth.user,
                    to:data['email'],
                    subject:subject_matching ? subject_matching.length === 2 ? subject_matching[1] : 'KvKit Submission' : 'KvKit Submission',
                    text:parsed_msg.replace(new RegExp(/\[(.*?)\]/,'g'),'')
                });
            }
        }

        kvkit.log({
            eventType:'New Data',
            username:req.session.username,
            data:JSON.stringify(data),
            ip_addr:req.ip,
            timestamp:new Date().toLocaleString()
        });

        req.session.submittedData = data;
        res.redirect(`/app/${req.params.app}/${req.params.kvstore}`);
    } else res.redirect('/admin/login');
});

app.get('/submitted/:app/:kvstore',(req,res) => {
    if(kvkit.forms[req.params.app]) {
        if(kvkit.forms[req.params.app][req.params.kvstore]) {
            if(kvkit.forms[req.params.app][req.params.kvstore].sharing.submission_template !== '' && kvkit.forms[req.params.app][req.params.kvstore].sharing.submission_template !== 'Choose a Template') {
                return res.render(`custom/submitted/${kvkit.forms[req.params.app][req.params.kvstore].sharing.submission_template}`,{locals:{data:req.session.submittedData}});
            }

            res.render('Submitted',{locals:{data:req.session.submittedData}});
        } else res.render('Submitted',{locals:{data:req.session.submittedData}});
    } else res.render('Submitted',{locals:{data:req.session.submittedData}});
});

// If the form has a file upload, it gets written to APP_NAME/KV_STORE/upload/[FILENAME]

app.post('/:app/:kvstore/upload/:filename',(req,res) => {
    if(kvkit.forms[req.params.app]) {
        if(kvkit.forms[req.params.app][req.params.kvstore]) {
            if(kvkit.forms[req.params.app][req.params.kvstore].sharing) {
                if(kvkit.forms[req.params.app][req.params.kvstore].sharing.public || (kvkit.forms[req.params.app][req.params.kvstore].sharing.private && req.session.formLoggedIn)) {
                    fs.exists(`${__dirname}/data/${req.params.app}/${req.params.kvstore}`,exists => {
                        if(!exists) {
                            fs.mkdirSync(`${__dirname}/data/${req.params.app}/`);
                            fs.mkdirSync(`${__dirname}/data/${req.params.app}/${req.params.kvstore}`);
                        }
                
                        let stream = fs.createWriteStream(`${__dirname}/data/${req.params.app}/${req.params.kvstore}/${req.params.filename}`);
                        req.pipe(stream)
                            .on('finish',() => {res.status(201).send();stream.close()});
                    });
                }
            }
        }
    }
});

// Get files that were uploaded

app.get('/:app/:kvstore/upload/:filename',(req,res) => {
    if(req.session.active) {
        let exists = fs.existsSync(`${__dirname}/data/${req.params.app}/${req.params.kvstore}`);

        if(!exists) {
            return res.status(404).send();
        }

        let d = fs.readFileSync(`${__dirname}/data/${req.params.app}/${req.params.kvstore}/${req.params.filename}`)
        let b = Buffer.from(d.toString().split('base64,')[1],'base64')

        return res.status(200).send(b);
    }

    return res.status(401).send();
});

// Gets the collection data from splunk into the apps variable which is sent to the app

app.get('/:app/:kvstore/getData',async (req,res) => {
    if(req.session.active) {
        kvkit.apps[req.params.app][req.params.kvstore].data = await kvkit.updateData({hostname:kvkit.splunk.hostname,port:kvkit.splunk.rest_port,app:req.params.app,collection:req.params.kvstore});
        res.send(kvkit.apps[req.params.app][req.params.kvstore]);
    } else res.redirect('/admin/login');
});

// Gets the collection's current configuration reading from the conf/forms.json file
app.get('/:app/:kvstore/getConfig',async (req,res) => {
    kvkit.forms = await kvkit.readJson(__dirname + '/config/forms.json');

    if(req.session.active || req.session.formLoggedIn || kvkit.forms[req.params.app][req.params.kvstore].sharing.public) {
        if(kvkit.forms[req.params.app] !== undefined) res.send(JSON.stringify(kvkit.forms[req.params.app][req.params.kvstore]));
        else res.send({});
    } else res.redirect('/admin/login');
});

// Returns the .csv file of specified backup

app.get('/backup/:app/:kvstore/:backup',(req,res) => {
    if(req.session.active) {
        fs.readFile(`${__dirname}/backups/${req.params.app}/${req.params.kvstore}/${req.params.backup}`,(err,data) => {
            if(err) res.status(404).send('Backup not Found.');
            else {
                res.contentType('csv');
                res.status(200).send(data.toString());
            }
        });
    } else res.redirect('/admin/login');
});

app.post('/backup/:app/:kvstore/:backup',(req,res) => {
    if(req.session.active) {
        fs.unlink(`${__dirname}/backups/${req.params.app}/${req.params.kvstore}/${req.params.backup}`,err => {
            if(err) res.status(500).send('Backup failed to delete.');
            else res.status(200).send('Backup Deleted Successfully.');
        });
    } else res.redirect('/admin/login');
});

// Converts specified kvstore to a .csv file & writes to backups/APP_NAME/KV_NAME-USER-TIMESTAMP.csv

app.post('/backup/:app/:kvstore',async (req,res) => {
    if(req.session.active) {
        kvkit.apps[req.params.app][req.params.kvstore].data = await kvkit.updateData({hostname:kvkit.splunk.hostname,port:kvkit.splunk.rest_port,app:req.params.app,collection:req.params.kvstore});
        let csv = kvkit.csv(req.params.app,req.params.kvstore);

        fs.exists(`${__dirname}/backups/${req.params.app}`,exists => {
            if(!exists) fs.mkdirSync(`${__dirname}/backups/${req.params.app}`);

            fs.exists(`${__dirname}/backups/${req.params.app}/${req.params.kvstore}`,exists => {
                if(!exists) fs.mkdirSync(`${__dirname}/backups/${req.params.app}/${req.params.kvstore}`);

                fs.writeFile(`${__dirname}/backups/${req.params.app}/${req.params.kvstore}/${req.params.kvstore}-${req.session.username}-${new Date().getTime()}.csv`,csv,err => {
                    if(err) {
                        console.log(err);
                        res.status(500).send('Failed Backup.');
                    } else res.status(201).send(csv);
                });
            });
        });

        kvkit.log({
            eventType:'Data Backup',
            username:req.session.username,
            csv,
            ip_addr:req.ip,
            timestamp:new Date().toLocaleString()
        });

    } else res.redirect('/admin/login');
});

app.post('/clear/:app/:kvstore',async (req,res) => {
    if(req.session.active) {
        kvkit.apps[req.params.app][req.params.kvstore].data = await kvkit.updateData({hostname:kvkit.splunk.hostname,port:kvkit.splunk.rest_port,app:req.params.app,collection:req.params.kvstore});

        kvkit.log({
            eventType:'Clearing Collection',
            username:req.session.username,
            pastData:JSON.stringify(kvkit.apps[req.params.app][req.params.kvstore].data),
            ip_addr:req.ip,
            timestamp:new Date().toLocaleString()
        });

        kvkit.delete({path:`/servicesNS/nobody/${req.params.app}/storage/collections/data/${req.params.kvstore}`})
            .then(del_res => res.status(del_res.statusCode).send(del_res.statusMessage))
            .catch(err => {
                console.log(err);
                res.status(500).send('Server Failure');
            });
    } else res.redirect('/admin/login');
});

app.post('/delete/:app/:kvstore',async (req,res) => {
    if(req.session.active) {
        kvkit.apps[req.params.app][req.params.kvstore].data = await kvkit.updateData({hostname:kvkit.splunk.hostname,port:kvkit.splunk.rest_port,app:req.params.app,collection:req.params.kvstore});

        kvkit.log({
            eventType:'Deleting Collection',
            username:req.session.username,
            pastData:JSON.stringify(kvkit.apps[req.params.app][req.params.kvstore].data),
            ip_addr:req.ip,
            timestamp:new Date().toLocaleString()
        });

        kvkit.delete({path:`/servicesNS/nobody/${req.params.app}/storage/collections/config/${req.params.kvstore}`})
        .then(rest_res => res.status(rest_res.statusCode).send(res.statusMessage))
        .catch(err => {
            console.log(err);
            res.status(500).send('Server Failure');
        });

        delete kvkit.apps[req.params.app][req.params.kvstore];
        delete kvkit.forms[req.params.app][req.params.kvstore];

        fs.writeFileSync(__dirname + '/config/forms.json',JSON.stringify(kvkit.forms,null,4));
        kvkit.apps = await kvkit.updateApps({hostname:kvkit.splunk.hostname,port:kvkit.splunk.rest_port});

    } else res.redirect('/admin/login');
});

// Collection Creation

app.get('/collection/create/:app',(req,res) => {
    if(req.session.active) res.render('Create',{locals:{app_name:req.params.app}});
    else res.redirect('/admin/login');
});

app.post('/collection/create/:app',async (req,res) => {
    if(req.session.active) {
        let fieldData = {};

        if(req.body.field instanceof Object) for(let field of req.body.field) fieldData['field.' + field] = req.body.field_type[req.body.field.indexOf(field)];
        else fieldData['field.' + req.body.field] = req.body.field_type;

        kvkit.post({
            path:`/servicesNS/nobody/${req.params.app}/storage/collections/config`,
            contentType:'x-www-form-urlencoded',
            data:querystring.stringify({name:req.body.name})
        }).then(config_res => {
            kvkit.post({
                path:`/servicesNS/nobody/${req.params.app}/storage/collections/config/${req.body.name}`,
                contentType:'x-www-form-urlencoded',
                data:querystring.stringify(fieldData)
            }).then(create_res => {
                if(!kvkit.forms[req.params.app]) kvkit.forms[req.params.app] = {};

                kvkit.forms[req.params.app][req.body.name] = {
                    sharing:{
                        public:false,
                        private:false,
                        public_data_view:false,
                        private_data_view:false,
                        splunk_search_user_auth:false,
                        public_form_template:'',
                        private_form_template:'',
                        roles:[],
                        post_process_search:'',
                        email_list:'',
                        email_msg:'',
                        email_submitter:false,
                        submitter_msg:'',
                        submission_template:''
                    }
                }

                let order = 1;
                for(let field in fieldData) {
                    kvkit.forms[req.params.app][req.body.name][field.replace('field.','')] = {
                        order,
                        form_name:field.replace('field.',''),
                        description:'',
                        static:false,
                        hidden:false,
                        required:false,
                        type:'input',
                        values:''
                    }
                    order += 1;
                }

                fs.writeFileSync(__dirname + '/config/forms.json',JSON.stringify(kvkit.forms,null,4));
                res.redirect('/');
            });
        });
    } else res.redirect('/admin/login');
});

// Orchestration

app.get('/orchestration',async (req,res) => {
    if(req.session.active) {
        kvkit.hosts = await kvkit.readJson(__dirname + '/config/hosts.json');
        kvkit.apps = await kvkit.updateApps({hostname:kvkit.splunk.hostname,port:kvkit.splunk.rest_port});

        if(kvkit.hosts.length === 0) {
            kvkit.hosts = [
                {
                    hostname:kvkit.splunk.hostname,
                    port:kvkit.splunk.rest_port,
                    username:kvkit.credentials.username,
                    password:kvkit.credentials.password,
                    apps:kvkit.apps
                }
            ]
        } else {
            for(let host of kvkit.hosts) {
                host.apps = await kvkit.updateApps({hostname:host.hostname,port:host.port,auth:'Basic ' + new Buffer.from(`${host.username}:${host.password}`,'ascii').toString('base64')})
            }
        }

        fs.writeFileSync(__dirname + '/config/hosts.json',JSON.stringify(kvkit.hosts,null,4));
        res.render('Orchestration',{locals:{username:req.session.username,hosts:kvkit.hosts,jobs:kvkit.jobs}});
    } else res.redirect('/admin/login');
});

app.post('/orchestration',async (req,res) => {
    if(req.session.active) {
        kvkit.hosts = await kvkit.readJson(__dirname + '/config/hosts.json');

        let options = JSON.parse(req.body.options);
        let split_names = options.src.split('-');

        let hostname = split_names[0];
        let app = split_names[1];
        let collection = split_names[2];

        let srcHost = kvkit.hosts.filter(h => {return h.hostname === hostname})[0];
        let data = await kvkit.updateData({hostname:srcHost.hostname,port:srcHost.port,app,collection,apps:srcHost.apps});

        if(options.action === 'merge' || options.action === 'append' || options.action === 'overwrite') {
            for(let dst of options.dst) {
                if(dst) {
                    split_names = dst.split('-');

                    let dstHostname = split_names[0];
                    let dstApp = split_names[1];
                    let dstCollection = split_names[2];
        
                    let dstHost = kvkit.hosts.filter(h => {return h.hostname === dstHostname})[0];

                    if(options.action === 'overwrite') await kvkit.delete({path:`/servicesNS/nobody/${dstApp}/storage/collections/data/${dstCollection}`})

                    for(let row of data) {
                        if(!options.keepKey) delete row._key;

                        kvkit.post({
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

        res.status(200).send(null);
    } else res.redirect('/admin/login');
});

app.get('/orchestration/add',async (req,res) => {
    if(req.session.active) res.render('OrchestrationAdd',{locals:{username:req.session.username,err:undefined}});
    else res.redirect('/admin/login');
});

app.post('/orchestration/add',async (req,res) => {
    if(req.session.active) {
        kvkit.apps = await kvkit.updateApps({hostname:kvkit.splunk.hostname,port:kvkit.splunk.rest_port});
        kvkit.hosts = await kvkit.readJson(__dirname + '/config/hosts.json');

        if(kvkit.hosts.length === 0) {
            kvkit.hosts = [
                {
                    hostname:kvkit.splunk.hostname,
                    port:kvkit.splunk.rest_port,
                    username:kvkit.credentials.username,
                    password:kvkit.credentials.password,
                    apps:kvkit.apps
                }
            ]
        }

        let host = {
            hostname:req.body.hostname,
            port:parseInt(req.body.port),
            username:req.body.username,
            password:req.body.password,
            apps:{}
        }

        if(kvkit.hosts.filter(h => {return h.hostname === host.hostname}).length != 0) {
            return res.render('OrchestrationAdd',{locals:{username:req.session.username,err:'Host already exists!'}});
        }

        try {
            host.apps = await kvkit.updateApps({hostname:host.hostname,port:host.port,auth:'Basic ' + new Buffer.from(`${host.username}:${host.password}`,'ascii').toString('base64')})
            kvkit.hosts.push(host);
            fs.writeFileSync(__dirname + '/config/hosts.json',JSON.stringify(kvkit.hosts,null,4));

            res.status(200).redirect('/orchestration');
        } catch(err) {
            console.log(err);
            res.render('OrchestrationAdd',{locals:{username:req.session.username,err}});
        }
    } else res.redirect('/orchestration');
});

app.post('/orchestration/cron',(req,res) => {
    let options = JSON.parse(req.body.options);
    let format = req.body.format;
    
    if(!cron.validate(format)) return res.status(400).render('ServerError',{locals:{err:'Invalid cron format!'}});

    let job_id = kvkit.randomString(32);

    while(Object.keys(kvkit.jobs).includes(job_id)) job_id = kvkit.randomString(32);

    kvkit.jobs[job_id] = {
        job_id,
        type:'orchestration',
        options,
        format,
        cron:null
    };

    kvkit.jobs[job_id].cron = cron.schedule(format,async () => {
        let options = JSON.parse(req.body.options);
        let split_names = options.src.split('-');

        let hostname = split_names[0];
        let app = split_names[1];
        let collection = split_names[2];
        let srcHost = kvkit.hosts.filter(h => {return h.hostname === hostname})[0];
        let data = await kvkit.updateData({hostname:srcHost.hostname,port:srcHost.port,app,collection,apps:srcHost.apps});
        
        if(options.action === 'merge' || options.action === 'append' || options.action === 'overwrite') {
            for(let dst of options.dst) {
                if(dst) {
                    split_names = dst.split('-');

                    let dstHostname = split_names[0];
                    let dstApp = split_names[1];
                    let dstCollection = split_names[2];
                    let dstHost = kvkit.hosts.filter(h => {return h.hostname === dstHostname})[0];
        
                    if(options.action === 'overwrite') await kvkit.delete({path:`/servicesNS/nobody/${dstApp}/storage/collections/data/${dstCollection}`})

                    for(let row of data) {
                        if(!options.keepKey) delete row._key;

                        kvkit.post({
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

    kvkit.saveJobs();
    res.status(200).send('Job started successfully!');
});

app.post('/orchestration/delete/:hostname',async (req,res) => {
    if(req.session.active) {
        kvkit.hosts = kvkit.hosts.filter(host => {return host.hostname !== req.params.hostname});
        fs.writeFileSync(__dirname + '/config/hosts.json',JSON.stringify(kvkit.hosts,null,4));
        res.status(200).send('Host deleted successfully!');
    } else res.redirect('/admin/login');
});

app.post('/orchestration/job/remove',async (req,res) => {
    if(req.session.active) {
       if(kvkit.jobs[req.body.id]) {
           kvkit.jobs[req.body.id].cron.destroy();
           delete kvkit.jobs[req.body.id];
           kvkit.saveJobs();
           res.status(200).send(null);
       } else res.status(409).send(null);
    } else res.redirect('/admin/login');
});

// 404 & 500 Views /views/NotFound.html & /views/ServerError.html

app.use((req,res) => res.status(404).render('NotFound'));
app.use((err,req,res,next) => res.status(500).render('ServerError',{locals:{err}}));

// Below checks license & starts the server...

(async () => {
    try {
        await kvkit.load();

        const server = https.createServer({
            cert: fs.readFileSync(kvkit.ssl.cert),
            key: fs.readFileSync(kvkit.ssl.key),
            passphrase: kvkit.ssl.passphrase
        }, app);

        server.listen(kvkit.server.port, kvkit.server.hostname, () => {
            console.log(`\nkvkit running\n\n - URL: https://${kvkit.server.hostname}:${kvkit.server.port}\n - PID: ${process.pid}\n`);
        });
    } catch (err) {
        console.error('failed to start kvkit:', err);
    }
})();
