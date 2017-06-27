#TRUSTED 409f89d045cd95ef2fe7060a19c2e5319ab639fdd1ca4ed02461f3a46eea2f3b53db40bf0ac2d12bf44cc055cd14acadb518bec028dc0a280a9179aca283c339dedac4782931f3d1754fbc8e58e1e80efcd70992fd89bc807ff8927e924f389672883e63e6d1fbbac835b14be61722da2cbc0b8ce348af429d365b189ffd1264ea31f13bf433ea3bf9b5c3cee5c16118f468755789b7924e624e502ef3e44ae54992fcec9db1da85f4098a1d6c62c8fa6aa71287c8f49c17e7eb6017aa07dadf04bb11fd349918140de06540cf397ff8d215839f6cf47705681a457ae2e0fc25048b92b2b422e3aa7e730b340cbda12146a6cd8b01f5b6a984f728c646add6b54583c7dc1b6dcd07cd8c011e810a3541459d4c3341ec7810fee526cebc665c8f50f8813dab3a52426cca4932e81c641eb79b5e0d729104f8b62c78eba2ec1531037bce3abadc87c2d79d4f7b1c2256c2c80144b49c2f83b4a39402225a4e489e421d3e1aaeafc70fb91b06978dd5c4a0ebb188a3d9a7d808686f3a78cf653905a3b23dd6960a49bd9fe5cd753f9737a0ada10eb57dd7e0734b6d5f32eb7d6da0185071f650c84a969a2dddee6bd72e555f37ee3f099fe0e25567126ea2beff1ab1c07e86fc189271d04ff962598aee51cb460146b3481aadceba2cce990b997033045767c1047308419c4f8a0a1df4af0ced7c1de4c87d904396adfa26947e95
#
# (C) Tenable Network Security, Inc. 
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15870);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: Cisco enable");
 script_summary(english:"Brute force Cisco 'enable' authentication with Hydra");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine Cisco passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find Cisco 'enable' passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 
 script_add_preference(name: "Logon password : ", type: "entry", value: "");

 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl", "hydra_cisco.nasl");
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

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv(socket: soc, length: 1024);
close(soc);
if ("Password:" >!< r) exit(0, "The banner from the Telnet server listening on port "+port+" does not have a password prompt.");

# Logon password is required
pass = script_get_preference("Logon password : ");
if (! pass)
{
 l = get_kb_list("Hydra/cisco/"+port);
 if (isnull(l)) exit(0, "No account was found by other Hydra Cisco tests.");
 foreach pass (l)
   if (pass)
    break;
 if (! pass) exit(0, "No account was found by other Hydra Cisco tests.");
}

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/cisco-enable")) svc = "cisco-enable";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'cisco-enable' service.");
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
argv[i++] = pass;

set_kb_item(name:"Hydra/cisco_enable/"+port+"/cmd_line", value:join(argv));

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
    set_kb_item(name: "Hydra/cisco_enable/"+port, value: p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following Cisco \'enable\' passwords :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/cisco_enable/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/cisco_enable/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the Cisco telnet server listening on port "+port+" to brute-force 'enable' passwords.");
}

if (!report) exit(0, "Hydra did not discover any 'enable' passwords for the Cisco telnet server listening on port "+port+".");
