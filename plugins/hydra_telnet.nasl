#TRUSTED 5067f380327cce0858509b17890e3a301754f1215765fb239e952bc8503d9334d599d6aa8758cb094150b987d055dc7f74733ff3ed14a0c8468b5a0a474ba2da4d4fea751571d2f692d3ec6bd8f4552ec27fdf427e04d914ed1f5bec62e55a0860813a78365c0a384a9074c3ed81ffafdfeb4851ba8f8e528a2ebad1d534848efc52af318720187811f7dc5d38b294c27a43f2ac57fe2beb521a535c73cef5061aaf152a56d9b2bf0103ab42fa5f29f4e4ab8b28c4c49acd85ec4148f6e1fcd9902a6ba05164aa7af0327c1b8e83621b79631304ef5b7938b60e94c2073611df7fc9230c5a6cf099a58538b481e8d40582a87d24b5d934607db10934c4557ec9fd9fb6040948afac71848b07d358f66f6f4c9b5adf2e32d289de9db2b0d167dc3055c364359d8c690eeba729f71f0c12116665734b09ba999f9779bab44e4b912fbeee58d7b108c7fd6eadadb7613fc5267c5dbabae587778b9a1f24ae4fe0cedd2cc84d0f2c3233e91b985608a6ca2326b7319bdde9a500e2e1dc9e3bca66fb8f6412100a0a619b04432c27eee07cd24b7ba0a85c4dd47ae0c67a7b528939455700d3db0b61a1de85a2e45a9e6a4fea19d9f169f86060ceadf5bb9a321869cd49ac1e624e9bcd7c1857b869775e7ae98d9e003c91d8da6f00502ba49af10a3178e22ce37239bf7aba604cbf5dd8d72481519a35714d5a2bab889de8da0d792f
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15889);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: telnet");
 script_summary(english:"Brute force telnet authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine telnet passwords through brute
force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find telnet passwords by brute force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "doublecheck_std_services.nasl", "telnetserver_detect_type_nd_version.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/telnet");
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

port = get_service(svc:"telnet", exit_on_fail:TRUE);        # port = 23?

# Check that this is not a router
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv(socket: soc, length: 1024);
close(soc);
if ("Password:" >< r) exit(1, "The banner from the server listening on port "+port+" looks like a router.");	# Probably a CISCO

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/telnet")) svc = "telnet";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'telnet' service.");
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
if (passwd != NULL)
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
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/telnet/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following Telnet credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the Telnet server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the Telnet server listening on port "+port+".");
