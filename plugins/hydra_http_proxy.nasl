#TRUSTED 2f5bb3612f8219121b9d3ef9d96b94582a918066af033ff1f2cf04ccae392b2ec365f46608cf3d2572f268915f2e5a5a0c926e925b54044200496bbd866bcea1f1c15df98a95f66902874bafb51647a511e2ed5fe028d43c7a0bdf3ad798db405afdafdbd7bb67fcaf0ef19183467308ea9487f2d35ae740ba72336b6749e33973b45cd0c72c77240e521aa91eb5c799efc93e717b90dcd47a98196a89cd72bc686892560be35d640b0c96d10867cf41b0c4ca4b1a8dc82bd78732fe5e55c2791fbb5b18433878bb8b072bfa23d81c148059bb559310b477398dce3182b38b4eeba818f8bcdf462a1c1fd7561db223cd8f4063a5cd368b7a41036995c893cf9af6db11b4f058f7410986e84d176aef090c61c7bb5c95b2b0e20a7e52fe8c0b99941d7c3380027cae5ed74d25d47d2a270c1a0009e6ab12fa613303a9261fe3348b315e8da59ddeb80e6e7b259ce15608586d4c3aa7ff695cb0193c10e16fda621969f251072fefaa36b3a8675ed8f3f9a272cd296ce20e2ecab68fbbadb6d0edf5d6a30ae7d8572890a19ed714517816bb245c6ababaea0c4564aaf078549f33fb51b67e111a90f17255270883718ece73b174789346ff45a523db8208cd476b02e90aa02d674f7f701902c64e110b0ce061663553af6a7443b38863f9607053da206d8014aead72e582a2aa18040b57b7a047679db99e1ae0d9983ce25759e1
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15874);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: HTTP proxy");
 script_summary(english:"Brute force HTTP proxy authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine HTTP proxy passwords through brute
force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find HTTP proxy accounts and passwords by
brute force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_add_preference(name: "Web site (optional) :", value: "", type: "entry");

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/http_proxy");
 script_timeout(0);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

force = get_kb_item("/tmp/hydra/force_run");
if (! force) exit(0, "Neither 'thorough_tests' nor 'force_run' is set.");

logins = get_kb_item("Secret/hydra/logins_file");
if (isnull(logins)) exit(0, "No Hydra logins file.");

port = get_service(svc:"http_proxy", exit_on_fail:TRUE);    # port = 3128?

# www.suse.com by default
opt = script_get_preference("Site (optional) :");
if (!opt) site = 'http://www.suse.com/';
else if (opt !~ '^(http|ftp)://') site = strcat('http://', opt);
else site = opt;
host = ereg_replace(string: site, pattern: '^(ftp|http://)([^/]+@)?([^/]+)/.*',
	replace: "\3");
if (host == site)
 req = 'GET '+site+' HTTP/1.0\r\n\r\n';
else
 req = 'GET '+site+' HTTP/1.1\r\nHost: '+host+'\r\n\r\n';
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

send(socket: soc, data: req);
r = recv_line(socket: soc, length: 1024);
close(soc);
if (r =~ "^HTTP/1\.[01] +[234]0[0-9] ") exit(0, "The HTTP proxy listening on port "+port+" is not protected.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/http-proxy")) svc = "http-proxy";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'http-proxy' service.");
else exit(1, "Failed to get the list of services that the installed version of Hydra supports.");

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
} else if (!s)
 exit(1, "No Hydra passwords file.");

if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

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
argv[i++] = svc;

if (opt) argv[i++] = opt;

set_kb_item(name:"Hydra/http_proxy/"+port+"/cmd_line", value:join(argv));

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
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/http_proxy/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following HTTP proxy credentials :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/hydra_proxy/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/hydra_proxy/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the HTTP proxy server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the HTTP proxy server listening on port "+port+".");
