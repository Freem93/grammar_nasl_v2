#TRUSTED 88daca7435e9ea2e80e276224c05fd8abaa60e05e3338a2d1d96737dada4545d808f7cb9c9c13c2bdf7a65a95c598c6a1fa580619794c492dda2eef062b84e0d21e2a90aecadce26ab5c92165dc078a368e03d001548cba0cd0919091b3f14a6faf1d4b48be8c38843d6d203f312d7375c192f516d0f2571c73fc819451ee5e38075b20c93222cce62b10f97f826898c0a1e5e9219d43496e2b5700e34f75dce335c02d06c0d7bb014410602b79ee946bd8215d62caa2e83304f581bd7bc23760fe12a14baf8956fb873dc2a78bfa88e49fd0a5236d7f5651ae9bdfb3a68a49a197b1c188568496f5853a268788c00ca7e581737caf4a3703ee54d8ca467a30a3ee88a5e2f9d3886bdcb9e3181eda67cf56e5c0330b3f2a11e4e0a12008965c4da33637b970f032723cc60f7e61c780421b5431ed9d7010c86a16ab6e10e41df4aaa426570277b37c0a98661cdb8990542c750b57b0655ce10c79215672598a76e936f643b5c7d4451daf362e3a2d2ae8207f438a52a83c0c7beb9e8339fed1a3d0b583faf31537e764cb30a6e496bf214ee669bbfefa058bb7432276b0acf8cd1640fea3422497e86aa95b7675b0468bea9064c0d021cff87100759646ccbc6898d28f4c54244a4d7fc50eb317e5d07b17f857d1a71edc5d0bc0bf47337da1cc2f286a431b323d2aa17accf1c8a0639b20aa25a55ba966cd819d9454de51fe5
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15875);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: ICQ");
 script_summary(english:"Brute force ICQ authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine ICQ accounts through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find ICQ accounts and passwords by brute
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

 # Currently, ICQ is not identified by find*.nasl
 script_dependencies("hydra_options.nasl", "find_service2.nasl", "external_svc_ident.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/icq", 5190);
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

port = get_service(svc:"icq", exit_on_fail:TRUE);           # port = 5190?

# We should check that the server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/icq")) svc = "icq";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'icq' service.");
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
    set_kb_item(name: 'Hydra/icq/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following ICQ credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the ICQ server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the ICQ server listening on port "+port+".");
