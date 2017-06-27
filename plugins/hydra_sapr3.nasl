#TRUSTED 04b8648efa3a84e9b0cd6687ae02568f9589588d39a4f89d72fc979c37ab52d85797f5440f6821da104f2e1f365737f16dd8acea5462d9ed9ccef4ef9667fdeb1d269e63e404c84f55d5d4248104e156ef8ebab4e74ff69222580ddbff20a87375704abcd340850a788db9dc0ea1521a3682f3973642438822fb4dd37f535bef92ec565b7d41eacb5f512a9e9ba46140b2cb92828379f6b53c8a074eb1b11f6853638f1a044db9df12102eb4f07414c32899eec6a730248806ef6416bb66bf86fddcafbf30a31977c01fc6a1fc727d1da947ea3b9652e1e9781b223f38d7d80fb039b6ab95a04a2cd887de08413262075ddc53dede6c607bb266ff9f867c98815e6e2e8f75a5d411e5d27640c54ede4e9d26a107fe7d2645bcc9e2b33b3885bdf20cb149106acc52877d67c87344edc5442cb3058e015b413774833313ce2af956b146d71623c20875bba503d68834e3345d8eddebaeb382b5d6462e36ccacd6d5f915181aa3263c534fd2402adcd7f371811b771a7f612e2547c9f5b7ed3b09ef90e7717ae39a334d38fb9de8c25f9c9c0c87da615f06f29154fc5cb8fc0018f007c323b09223c23e592b5887bb1a2e9cf1d4602d90d2a1b63b7737a969ec400f4ea1a9842deba768b5985e33f826ee52d2b98d2f371c16a810a46fb1353815d5c2d8391b599704b6fbfc1bc245aaf6d53e2ad4eba16497d44442c4dd213163
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15883);
 script_version ("1.11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: SAP R3");
 script_summary(english:"Brute force SAP R3 authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SAP R3 passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SAP R3 accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_add_preference(name: "Client ID (between 0 and 99) : ", type: "entry", value: "");

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "external_svc_ident.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/sap-r3");
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

id = script_get_preference("Client ID (between 0 and 99) : ");
if (! id) exit(0, "No Client ID was provided.");
id = int(id);
if (id < 0 || id > 99) exit(1, "Invalid Client ID ("+id+").");

port = get_service(svc:"sap-r3", exit_on_fail:TRUE);        # port = 3299?

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/sapr3")) svc = "sapr3";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'sapr3' service.");
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
argv[i++] = id;

set_kb_item(name:"Hydra/sap-r3/"+port+"/cmd_line", value:join(argv));

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
    set_kb_item(name: 'Hydra/sap-r3/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following SAP R3 credentials :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/sap-r3/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/sap-r3/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the SAP R3 service listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the SAP R3 service listening on port "+port+".");
