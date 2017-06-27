#TRUSTED a38cfeb529a0241445d0a9227f72418728a2250f3b37dc797daf9f47dda3ab96e0d965500c8199c169d0feef07a2c580fd9c9fc4bd2d82331fa371cc317fea051e4bf429b20e11010b7f07d6d9832efc071adf59509988fa55d138cd564427b0b4395ec98388370b1d74ecbba65da9718d994101a71bf5a138f815d20569c96f895eb111ed0b546b9d2ed0d89919f74d35b0563c8fd33b00401fb01b3385af409b67bf9b15d35554567308a15fa447d6e9a2407d126a13ed101135551a3bec38fe484ea434e2381e44fa2c1cf5d55d96bdaac3f3785b70faad9278da6409982c54ae412c8a51d9e4b30451ad7867c185ca18394db0d714d601663c47aeeca5776e13590c457716c5d0c69ec786b6b30df4e5adcf509e3881502206d89eef1c56cfa56f70d638d63c6b9ebfe0908bc720641185d19ce43e7c3d78e70c5ce34055e252ad3404782833a803853a047a742de3d73da518d6a8999031fb842ff7821fcdec90cabb153960ad6e30e4792b1791c8f46c5ddcffaac431e86b20a63e6959584edd415fd5d2dba4f5e5793e4d2c7e5b4493ef47fe5e112528e4b38449617b130ae02378fae1d34d55236cfcfe96556dce498001b8e292457f8405def7478cd2de3569c52424f5fa00c89cb0d6dbec9d1c4d32066335987a08e6938adf33880b73ef53cb7296e72be046e38ffcb00b36abfca076d246f6b9e8ca78ec30aa4d
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra")) exit(0);

include("compat.inc");

if(description)
{
 script_id(15888);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: SSH2");
 script_summary(english:"Brute force SSH2 authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SSH passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SSH2 accounts and passwords by brute
force. 

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

 script_dependencies("hydra_options.nasl", "doublecheck_std_services.nasl", "ssh_detect.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/ssh");
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

port = get_service(svc:"ssh", exit_on_fail:TRUE);       # port = 22?

# Check that the server is up & running
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv_line(socket: soc, length: 1024);
close(soc);
if (r !~ '^SSH-') exit(1, "The banner from the service listening on port "+port+" does not look like an SSH server.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/ssh")) svc = "ssh";
else if (get_kb_item("/tmp/hydra/service/ssh2")) svc = "ssh2";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'ssh' or 'ssh2' services.");
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

set_kb_item(name: "Hydra/ssh/"+port+"/cmd_line", value: join(argv));

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
    set_kb_item(name: 'Hydra/ssh/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port: port, extra:'\nHydra discovered the following SSH credentials :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/ssh/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/ssh/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the SSH server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the SSH server listening on port "+port+".");
