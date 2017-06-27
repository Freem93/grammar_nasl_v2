#TRUSTED 491fc8015ed07a2d2a41641e843418361b6b8b33de9a7d6a5f699b4b7072be50fcb48f3463e1442147c8df40522a0a78260719d339e62be70fc2b59c436f7dc49641b55a8579f139fff7f5485cbfc3f14784ce62ae1ea662950f99cb2fdc8e7b1097c1fa607f66d5257f5d26e3ce4321d4ad0f067d319e0e97ba28c1010ce0667f254fd50298b03dfe7dbfc56632197c87b509cebb92ab9749e6b05d4738677185229cb161cc216120b91f163b029906fdca62dc7f5bdfcf2ad95462edf8ff61e48e65fab59e24a12fbc3bff267b50c1a4887f88dd4d4f5d703dcdcb3c41a119d93a9216a3f342d1e85524803635da9a19288f36a4e0856a24a7f4e2b06990f124c859fa5b14c73139bbf9cbdc7d989a5e30ac128e8f43b8cc8709e330a615e1c29346578c5bb118e7698a847a530da933a5a675b1f735ff9634698944c9928cab830d14c1133a2c1910ac92633fa7abb1340eff5466c4ba9289650d1d3d1e1ef3a500166fe625fe795be11ca344178fc4b9e6e45ddcacd66e867d56cdc1dbfa5d7c9f6f8356fe011b2ef673e31472d31e23e081dfa95cfe640fe3328720b96f383c75e045a9c1b1367e787493c2be14a3949fe804dacdfded320c084b189656ba3d95a7f454534df3d4fe078ae58bc23619b742ebd0bf9997ae1024351f3655eff62f6d5c24ccca7847f34507974fd2a74c7c74e2a8c8a3e5f77eea5d375569
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15884);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: SMB");
 script_summary(english:"Brute force SMB authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SMB passwords by brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SMB accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_add_preference(name: "Check local / domain accounts", 
	value: "Local accounts; Domain Accounts; Either", type: "radio");
 script_add_preference(name: "Interpret passwords as NTLM hashes", 
	value: "no", type: "checkbox");

 script_category(ACT_DESTRUCTIVE_ATTACK);	# risk of accounts lock out
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("SMB/transport");
 script_timeout(0);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

force = get_kb_item("/tmp/hydra/force_run");
if (! force) exit(0, "Neither 'thorough_tests' nor 'force_run' is set.");

# Because of accounts lock out 
if (safe_checks()) exit(0, "safe_checks is set (risk of accounts lock out).");

logins = get_kb_item("Secret/hydra/logins_file");
if (isnull(logins)) exit(0, "No Hydra logins file.");

port = get_kb_item("SMB/transport"); port = int(port);
if (!port) exit(0, "No SMB server was detected.");
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/smbnt") || get_kb_item("/tmp/hydra/service/smb")) svc = "smbnt";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'smbnt' service.");
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

opt = "";
p = script_get_preference("Check local / domain accounts");
if ("Local" >< p) opt = "L";
else if ("Domain" >< p) opt = "D";
else opt = "B";

p = script_get_preference("Interpret passwords as NTLM hashes");
if ("yes" >< p) opt += "H";
argv[i++] = opt;

set_kb_item(name:"Hydra/smb/"+port+"/cmd_line", value:join(argv));

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
    set_kb_item(name: 'Hydra/smb/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following SMB credentials :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/smb/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/smb/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the SMB server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the SMB server listening on port "+port+".");
