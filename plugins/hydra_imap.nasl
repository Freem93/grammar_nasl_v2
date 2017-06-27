#TRUSTED 5fd9ad8c353170df77bccc52eb4a49992656921089cc21c95d16fb420c0afd292109e99d9fd2df512286f74d4bd410d46ef9a23d395bd1216c0d1135c4d2c88e102c0112609413b5382876668b7c55bd27ce033eeaed35e6b074b08baf29cd09e1f8b31ff3f79e52ae012ec88df324d980a77cdef07dd9344fec4cc754bf5b6b1428c95c5bb4fb7ebe87df486b9b2ce35e3c8763924a0ecdcab684b4d3e9198b22cda3c3800c4362b591352e94c5cd9232336936a2721dab83ce8356afa4ddcb6132ef64b44d8f00bfc45cf2f33a11a8fb3d7a32a00a244082fa4fd46f49f20dd76d2855f69ae109dd1b1f04ebd7683a76556ad096870b8d3b46b6d9368eba0925b455e1614cff178402333be27de3841fb6318e9d6d3b82fbc4cba170258d2ab71c03c0b90e50635c0f4ac83cde9f251fd535d9e75a0e3059180c2c27d6de3d67ebf3d48665a8f730e327e0a97bacffa7587d3fd171fbd8277c665d0397d92dfbc89534fee1f2ea2e90389f05a2dfc6cf63940864302429976d7f279dbc6fcf60224bc20623e263527af860b7f53f7af7c2574ba990e4be221c454f46177957ed2371402361f15f56934c6fe409203254b120a2b637cd6d13baae504e59f7892bc7d303278539863a8e3cfda377a6f94ac3929708ecc5b17766cfa2fb105d23901339f17696c68c0d62e329e665656a18511d733acf89ec82e991432fbdd7d1
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15876);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: IMAP");
 script_summary(english:"Brute force IMAP authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine IMAP passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find IMAP accounts and passwords by brute
force. 

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

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/imap");
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

port = get_service(svc:"imap", exit_on_fail:TRUE);          # port = 143?

# Check that the server is up & running
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv(socket: soc, length: 1024);
close(soc);
if (r !~ '^\\* *OK ') exit(1, "The banner from the IMAP server listening on port "+port+" indicates a problem.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/imap")) svc = "imap";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'imap' service.");
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
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/imap/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |ERROR [0-9]|Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following IMAP credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the IMAP server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the IMAP server listening on port "+port+".");
