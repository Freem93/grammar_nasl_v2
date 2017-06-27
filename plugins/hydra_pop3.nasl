#TRUSTED 6c18b64e9041acd9b4e559116c9bb69f7d0529926b0a92d0f49075dfa479a906574d9f5aa07cb1ae26adae75f660615347097cce292ea027e8ef3bd19c975b075e36dc806ea05009c23bd50645e4f13e8a790302afb9af0b4d344d40ccf2d6114cd9daef02dee945cbc8bd70e11e8ec398f7b912ccb2df002d39ae1a51953dd6332465d61b53e8ca2bffcef5d4652b20ef17d8c142ff58bb3d761fee84f9a4d9a1183f37fcf2d6d8cd58cd5b720c96ea908c08c65de88244211aa7000cb11f8473485555090fc77e8530065c7c01bb372d07cd178fe9a5ebd36e81500268dc2e52d5ca2bc7aa6eb35fe6ef164b381fbc4b49f17bc66e14dafc08fa97a2e5bb22f7fa50566e483b9f0d47ac2e5448c55728a5211071e3b60198dce036b74bda70d5944ebc507134ed6db189f6cd4f4e38041e0d8c1b2e5360c1ec509f48552ee99bbaad64cfb43ddadde642f86423e6c9ec567d52fd42b700b2f143d65d17caa6e7b0633d864ccec66ef460573dc07797ee5062da33bee957d10fa0f4e75ef54e92c2cb815493ade83abad217da7dfc018bbd4d775a8c999820576720cce0ab02a600dcdd5eff43ffcebe7b02b8370a51ac19b10fcdf5e717dfbeaa43e3cd87926989ec33d539305075cfb048e9abfc7a3ce3c7aeab400dce55001f4eb2f4c043cca0d2b630f9fb26b71c4bad95bb347d4cdafa96a27342646c8e3587146a2f17
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15881);
 script_version("1.11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: POP3");
 script_summary(english:"Brute force POP3 authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine POP3 passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find POP3 accounts and passwords by brute
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
 script_require_ports("Services/pop3", 110);
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

port = get_service(svc:"pop3", exit_on_fail:TRUE);       # port = 110?

# Check that the POP server is up & running
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

line = recv_line(socket: soc, length: 4096);
close(soc);
if (line !~ "^\+OK ") exit(1, "The banner from the POP3 server listening on port "+port+" indicates a problem.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/pop3")) svc = "pop3";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'pop3' service.");
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
    set_kb_item(name: 'Hydra/pop3/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following POP3 credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the POP3 server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the POP3 server listening on port "+port+".");
