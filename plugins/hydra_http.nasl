#TRUSTED 3cb3c113d65cc22f2f007eddb4e892c27ba826ea720d3dcd3380a8dfe6fcfa1398cd9c24cf5e10b1739919f87e5a1a4c0c69866e75d95553ef30d713fd97abff0a61d04b9a05c3cff092e9f868f835d97a35b4e17aa2ee95cb80a4d0d522ae727a0f941304642689ff203403d8b330cf6289ccd303498e32200f6d2bb9caa1c491afd5d9fd0152df35e6b6b3e8de091d95d4e282a9e2fe47c733f9f5a64509d25af572cc8c565d4b0b5aa10420ee7925279ada749cdaa88fe141089c0692830f06c3ec6a145987732d02877d53abb03aabfc85da4d843105ef8e590413976f881e23657a57d3c6ad668774af60c88b3e7deea1bf7fc867606f525246a5091ec8c9367c0952f18f8b8d506d8e87802d8629b7c09d82510ab82092e992862e6643befc67e1be580be480de4e48b70dd7e23c08fd62ef2c69956eab296ec7bec16719f62b5c9b0ae028ccaca5f734a6c79e4d2e43177081dd006cb8ddac92ea9a037c65938c444516aedbbb34adc84a45cb77f386b5da279626f63493b956a1afcd3233fc443818f0221af1bab7a26e22111a5fa00d13644a95d41ad7de721e6728da29c92bde1210ad53bf5508a6bdffc6480748021e3fcc7e2bb6d9a62da2a9a1f6a76ebd1f9ca45bf5cdd75b04d9335bc63b77a780e5acba81aeed58c74c735d703a3e42c7391c1632d71acf8aaf7530f79c4d43d136313cb14dbdd1daa18d08
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15873);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2016/03/16");

 script_xref(name:"OWASP", value:"OWASP-AUTHN-004");
 script_xref(name:"OWASP", value:"OWASP-AUTHN-006");
 script_xref(name:"OWASP", value:"OWASP-AUTHN-010");

 script_name(english:"Hydra: HTTP");
 script_summary(english:"Brute force HTTP authentication with Hydra.");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine HTTP passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find HTTP passwords by brute force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:
"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_add_preference(name: "Web page :", value: "", type: "entry");

 script_category(ACT_MIXED_ATTACK);
 script_family(english:"Brute force attacks");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencies("webmirror.nasl", "hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/www");

 script_timeout(0);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

force = get_kb_item("/tmp/hydra/force_run");
if (! force) exit(0, "Neither 'thorough_tests' nor 'force_run' is set.");

logins = get_kb_item("Secret/hydra/logins_file");
if (isnull(logins)) exit(0, "No Hydra logins file.");

port = get_http_port(default:port);

res = http_send_recv3(port         : port,
                      method       : "GET",
                      item         : "/",
                      exit_on_fail : TRUE);

if (res[0] !~ '^HTTP/1\\.[0-9] +[0-9][0-9][0-9]')
  exit(0, "The banner from the HTTP server listening on port "+port+" does not have an HTTP response code.");

timeout = int(get_kb_item("/tmp/hydra/timeout"));
tasks = int(get_kb_item("/tmp/hydra/tasks"));

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-L"; argv[i++] = logins;

s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}

passwd = get_kb_item("Secret/hydra/passwords_file");
if (passwd)
{
 argv[i++] = "-P"; argv[i++] = passwd;
}
else if (! s)
 exit(0, "No Hydra passwords file.");

if (exit_asap) argv[i++] = "-f";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
if ( tr >= ENCAPS_SSLv2 )
{
  if (get_kb_item("/tmp/hydra/service/https-get")) svc = "https-get";
  else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'https-get' service.");
  else exit(1, "Failed to get the list of services that the installed version of Hydra supports.");
}
else
{
  if (get_kb_item("/tmp/hydra/service/http-get")) svc = "http-get";
  else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'http-get' service.");
  else exit(1, "Failed to get the list of services that the installed version of Hydra supports.");
}
argv[i++] = svc;

opt = script_get_preference("Web page :");

test_urls = make_list();

if (opt)
  test_urls = make_list(test_urls, opt);  

if(!opt || thorough_tests) 
  v = get_kb_list('www/'+port+'/content/auth_required');

if(!opt && isnull(v))
  exit(0, "No HTTP protected page was found on port "+port+".");

foreach url (v)
{
  if(!thorough_tests && max_index(test_urls) > 0) break;
  test_urls = make_list(test_urls, url);
}

opt = branch(test_urls);

res = http_send_recv3(port         : port,
                      method       : "GET",
                      item         : opt,
                      exit_on_fail : TRUE);

if (res[0] !~ '^HTTP/1\\.[01] +40[13]' ||
    'www-authenticate' >!<  tolower(res[1]))
  exit(0, "The page "+opt+" on port "+port+" is not protected by HTTP authentication.");
#
argv[i++] = opt;

set_kb_item(name:"Hydra/http/"+port+"/cmd_line", value:join(argv));

errors = make_list();
report = "";
results = pread(cmd:"hydra", argv:argv, nice:5);
foreach line (split(results, keep:FALSE))
{
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = '\n  Path     : ' + opt + 
             '\n  Username : ' + l + 
             '\n  Password : ' + p + '\n'; 
    set_kb_item(name: 'Hydra/http/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following HTTP credentials :\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = msg + error + '\n';
  }

  set_kb_item(name:"Hydra/errors/http/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/http/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the web server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the web server listening on port "+port+".");
