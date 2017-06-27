#TRUSTED 180f413d2ba7da9ceedf2f39839246d2bc834ae649ba244a1c78883826950a599e85625b1ea9dd278400c787a2b06abb14e617aad1f239c2684f162ed839eea4dec8760032c5acfc36d915f05b799426c5ffd5514aad2e03aaf0b3a2927277fc74760e30edc6a868e1c787547b188189fdad25b1e44dfe48ebdafef35c1edf13606651792dbd6ddfa09ab17bd61be222a89c02ab5b7777662912a69f45c32e7308d000d6ae62fdce919ee7748f5e1321e647e9bd86618654465d7f60ce141b13c6f0f825606f9422ff81bc5fad7779482b521ee7d9efa4b5480c94d354c4c92b634a0516b4c83a190db2b5448b65782c5387dd2161826eaebe306b4579e897cbb757a1d52e1fe8a8e6429f98f3a1e96a3e3ca93d5de240d945651c8ebb4fcc32ab462c100fb080acb524ddf0a470098c72e6598603d52b2c1317510318553d979943c9aad67337efe9b62c6e8ca526be4bcd54e80386de264804a1cdf3f6dfba601b2ce227a1c00082fd60af992cca98dee18bc784e99652e62c89427ce62bdc36e4fef4966ec4ae92ee16292ba11468d245e2c0f642bea389e25cfa3cec9f3e38a6a5cb6c9b477f5f76dacbac75ca468b4fa0ece2a89b5ac58812b9509135db6f98107d76eafa73db993f983b1ecf24b2ef092737b617af22c4a21b8031359f772bf28f2713f80b355e5d3113f35515225d668714f45989a4e2089df1372df2
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15869);
 script_version("1.8");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: Cisco");
 script_summary(english:"Brute force Cisco authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine Cisco passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find Cisco passwords by brute force. 

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
 script_require_keys("Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/telnet", 23);
 script_timeout(0);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

force = get_kb_item("/tmp/hydra/force_run");
if (! force) exit(0, "Neither 'thorough_tests' nor 'force_run' is set.");

port = get_service(svc:"telnet", exit_on_fail:TRUE);       # port = 23?

# Check that this is a router
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv(socket: soc, length: 1024);
close(soc);
if ("Password:" >!< r) exit(0, "The banner from the Telnet server listening on port "+port+" does not have a password prompt.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/cisco")) svc = "cisco";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'cisco' service.");
else exit(1, "Failed to get the list of services that the installed version of Hydra supports.");

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
if (empty)
{
  argv[i++] = "-e"; argv[i++] = "n";
}
passwd = get_kb_item("Secret/hydra/passwords_file");
if (passwd)
{
 argv[i++] = "-P"; argv[i++] = passwd;
} else if (! empty)
 exit(0, "No Hydra password file.");

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
  v = eregmatch(string: line, pattern: 'host:.*(login: *.*)? password: *(.*)$');
  if (! isnull(v))
  {
    # l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, p, '\n');
    set_kb_item(name: 'Hydra/cisco/'+port, value: p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following Cisco passwords :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the Cisco telnet server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the Cisco telnet server listening on port "+port+".");
