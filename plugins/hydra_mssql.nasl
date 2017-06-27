#TRUSTED 0b94b7a4d207aeb61580de6ea42f00324738fb7205930c1a527668a73d69991e37a87468c9a89f6df65dbc615b22b0cbe39d00ce3b0e6c0852ead9ace08b85cc7706b7f5767265868764a402fa14661960b9478f2589b1135dabd7bf2bfec367dbebbdae7ad989c4f9663a8716d105f5448855c4d8e15d5b7f846a886ca1e22b1ebcc4cdcfb171109c733214f27cf1b5a9438fb9f7f96edababde7ec63109860e22c25766dec14634a3b8b74ddb0983d4c2fbc7e2fcf11e35a5f48d0bdf455067cc639619be88e506ecf73ef7f8db3c159048cdf44040c228a174569e745b556fb8e8e6817302ca0343b56808b2eb7e58b993a28b322426e74766d35b3d49487d58f5bac31c8f09d3fc046af6d4a53fe7f250006bd0b1eb21b32a73610185ecc574d0c72caff6d39ba0883b44ad37c96b01f767f899e2e6bba250ba4fc487570ba5b40f9a9eb576151dc7a2d2422438b569f19847928903c73c413cf711fcdcb68429554045dbda0ce609228b04cdffe89b9c0e285b18a7e37bbc9e59ecca12ee031e274f67af64b469266eaacec411348983df5ca43c8a4be8bec5bc8f98ac36ae2bb86bbac7138d1de0bc6042a41c8aaf487056beafd473fb3b1e888fad353f617d441d9bdd6ea2175c20b73ded2ac7b4a7b1f9ec41b27b2a67cbcee71adbdedfb7b03f3b71be3a0730a1bc95990d0a3f51f6216c85c19186bbf4bb5e30195
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15878);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: MS SQL");
 script_summary(english:"Brute force MS SQL authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine MS SQL passwords through brute
force." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find MS SQL passwords by brute force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "mssqlserver_detect.nasl", "mssql_blank_password.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/mssql");
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

port = get_service(svc:"mssql", exit_on_fail:TRUE);         # port = 1433?
if (get_kb_item('MSSQL/blank_password/'+port)) exit(0, "The MS SQL server listening on port "+port+" has a blank password.");

# We should check that the server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/mssql")) svc = "mssql";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'mssql' service.");
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
} else if (! s)
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

set_kb_item(name:"Hydra/"+svc+"/"+port+"/cmd_line", value:join(argv));

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
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/mssql/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following MS SQL credentials :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/"+svc+"/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/"+svc+"/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the MS SQL server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the MS SQL server listening on port "+port+".");
