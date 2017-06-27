#TRUSTED 70ccded05b9127c2991d8171ac7c366ef13d55804a67d3a6edec30c87b935f13a424b1de04f2df53aa3402d68bf169d7a9fb78c1bdc36874baa4270df9fe0362b23d77fa67a42112fb33d8b097b3006df1704ebcff97d66fc4877b71ea5c0531ab97fe25afd1ecd3c0690d1d030e000970bf41f06b0e5b1399ddf0bbc1479476a7facb84bb5aba264f37a7d53d778fbbdf4240a4dbf0b18d63f4b8d2f8d019074d204422180df947f2e5a8300da5aea6147dbd1ace55745223f37d066720c64e69d510405f916e0b02f54d7a07946e87b36c1c250384b986a0886f28a18b727e34f03321c7b5b357db12ded8dfec7155e24c9ad2bc8fb112f7d8b907ae9986e9d6de91b97ed847684afdb2a754380ea190c7140af078a58eed22191b5cb4bba74e3befe8580b9c01d4970d18781b2127ba6ac2d4420fd54f25118b01d5fd39dcad797be95ffe7ac1cc55679cf7295cf6b6f2d8ae8d8f38033691ceb48b4222ad20d814b55f6c8c7bfbb002476ae8f3006e2978544c2a3c8cfc094d882f5e7a11022284722453092d6c1a0f8956f4a080fa9fe57ad75334678759a13fafb539aa2f1c4b9bd63a30832b0cc00896ef99207fcd368c78d627983fcf09e8dac6925d486544dbe8bc8ac8b237972c206f54cff886321318669f0459f1e047c4741a2485fefb0cf6a8b43735ff245076db24f55a916506ed61a86335e2b2d240ec299c
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15886);
 script_version("1.11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: SNMP");
 script_summary(english:"Brute force SNMP authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SNMP passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SNMP passwords by brute force. 

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

 script_dependencies("hydra_options.nasl", "snmp_settings.nasl");
 script_require_keys("Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_udp_ports(161, 32789);
 script_timeout(0);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

force = get_kb_item("/tmp/hydra/force_run");
if (! force) exit(0, "Neither 'thorough_tests' nor 'force_run' is set.");

port = get_kb_item("SNMP/port");
if (port) exit(0, "The SNMP community name is already known on UDP port "+port+".");
# Yes! We exit if we know the port, and thus some common community name
port = 161;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");

if (get_kb_item("/tmp/hydra/service/snmp")) svc = "snmp";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'snmp' service.");
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
 exit(1, "No Hydra passwords file.");

if (exit_asap) argv[i++] = "-f";

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
    p = chomp(v[2]);
    report = strcat(report, p, '\n');
    set_kb_item(name: 'Hydra/snmp/'+port, value: p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, proto:"udp", extra:'\nHydra discovered the following SNMP communities :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the SNMP server listening on UDP port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the SNMP server listening on UDP port "+port+".");
