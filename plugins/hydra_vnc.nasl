#TRUSTED 0a8bd45c6bbeb5888bd129f4dcedf2bbab9b322d825ce7f9b4f6d1f3fd8e8ec42cd47102ddec8fe0046ba913958154487b3f46fab1f2417ef4e194d6c41a6e042431ad053b6f2aaf5bb8159e1165c60072f2b6e5481a2df7b4b4c5a1f4795c0c1d3e47b62104db9ad063f46cb497906f7dc0ac9e4ade678f7094b9a95bb5061252c2333973e1a95af7650f7045dc9391a799e3689285e6acd4def463d7c725f37e319d6cef9836456c47a13f9ac1519480c16b9e57d44b40f36020ebfce28036019b7a02014ff9e73371dce7d4dc6c4c4ea1954436cc5ee5aec7e8f2534ab9f9a027f4409a3776ffc9c89c900ca8b246056250d02e9ff1ffa7d51b553fe669ee28d9c39336e849c0ca53be9461bd4888347a4ae52884b5631c50b1b72fccc299bfc77aeadecf4536b32f6d1583437ee5cd781feb72653b9726b2dc7303812c0a51da8a431e2c55c3e83765c2d046166e7a4f5383e1a78f13f951e9348d8d01ad1dbd5e7d9166ea4ffb771913ee0286eb8216396e62e81e3b28b7c88ad8de81ef250215ee14801de320d5589ea2e518413d897ad32f37da5409698e87e3b72a282385c5c18cbd4150a8992b0017d7f853c2f6f1fe368a0e9c16e904d2f2c2ef3cd8e1b529bf3d835873e98f34c0e5a22626d24e37a5b662a3640e4086d7e3441d234953ad5a753eea9c92c40a8612f67f89d9c6062598067d8875459ae8cc5878
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15890);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: VNC");
 script_summary(english:"Brute force VNC authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine VNC passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find VNC passwords by brute force. 

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

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl", "vnc_security_types.nasl");
 script_require_keys("Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/vnc");
 script_timeout(0);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

force = get_kb_item("/tmp/hydra/force_run");
if (! force) exit(0, "Neither 'thorough_tests' nor 'force_run' is set.");

port = get_service(svc:"vnc", exit_on_fail:TRUE);           # port = 5900?

st = get_kb_item_or_exit('VNC/SecurityType/'+port);
if (st == 1) exit(0, "The VNC server on port "+port+" is not password-protected.");	# No auth

# Check that the VNC server is up and running
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv(socket: soc, length: 512, min: 12);
close(soc);
if (strlen(r) < 12) exit(0, "Short read on port "+port+".");
v = eregmatch(string: r, pattern: '^RFB ([0-9]+)\\.([0-9]+)\n');
if (isnull(v)) exit(1, "The banner from the service listening on port "+port+" does not look like a VNC server.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/vnc")) svc = "vnc";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'vnc' service.");
else exit(1, "Failed to get the list of services that the installed version of Hydra supports.");

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
s = "";
if (empty) s = "n";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}
passwd = get_kb_item("Secret/hydra/passwords_file");
if (passwd != NULL)
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
  v = eregmatch(string: line, pattern: 'host:.*(login: *.*)? password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, p, '\n');
    set_kb_item(name: 'Hydra/vnc/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following VNC passwords :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the VNC service listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the VNC service listening on port "+port+".");
