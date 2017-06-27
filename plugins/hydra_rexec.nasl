#TRUSTED 6488b219839982af4eddd1cf0ad6f3f99416e4bc267815deafb7b951acd8c12260b23cda4be00e6a2fceb18a2223f44bffb499cff5abe2ffc05a39835273d7c647f5f95259dc5df06a5af1c58cf6b73145198f40e982077be5e36da0a9cfca5342346cc4ee2287c6b7fecee38c4a91141285f902f81798add203d03d62fb1513781fe70e70445d2206deae4f0112701b0dc261806d0bdc6344ba46d93ef809fdd853a335e4ac7374e4d6f1fb0e453574ad71d1b5f682d0ff4feab1bfdf0a8dbdb1488d2a1eea245e147cf7ebc86d42fd31edad05a8cde2d105b5ec49fe673627c9d1998b89826f117f3a4465e0c7e96226c32bc3fc2ee431f6a2cd7de1dfc00b8e4f0fbad73064670ae5a87a32aee27ab064101e351116836f097f6bc366457f6240b1d5609224c800de17b4e01731f5217c567f559e8a0adc243cbf1d7f390cfa436289f44031c064fc1760a92e7379d13defa96929014718526c2ec0428794ae5a2af63892b410071e673d0d2b1c6434cfd0b12270ae5531c55316620be9fcb1bebf7385c3193976c49ada7c27806f22fae87fa6c74692bee7c8b5477642c910160b8b08c7b94b9ff7eabb174a90139ad1c732702a2902652dc324f8fd729f17ced09479e1d7e1dca4a82882a3714348d7abfe7ab652649f5ca22404c46e21dbfd8bc9bd4a8272844b5ddcad7a136113a2e5e62a94040a35f5040fba0a8478
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15882);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: rexec");
 script_summary(english:"Brute force rexec authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine rexec passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find rexec accounts and passwords by brute
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

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "rexecd.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/rexecd", 512);
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

port = get_service(svc:"rexecd", exit_on_fail:TRUE);        # port = 512?

# TBD: check that the remote server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/rexec")) svc = "rexec";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'rexec' service.");
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
    set_kb_item(name: 'Hydra/rexec/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following rexec credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the rexec server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the rexec server listening on port "+port+".");
