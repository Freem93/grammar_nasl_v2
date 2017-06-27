#TRUSTED 213a50975b3124b6aedc197a2b9b4d38965a671a93a20390d9c9d1093258e99a751170696d0b4aecce27561f4936436350ac133c00f361ea3f1ad75dda0b92d464b61c83da21cb9d49652f6dfdbaef1b23e3f81b3ce213d9c863de42b5bbedc73e85eba9f297e6965880dc475da3d2292da03876f836b0d23bcb7519b12f03277a223cdaa1d5a9210c286c5efc11ca29971fa6ef01848ab0e111e98a819cfcbe374d5896db288ade9960e3d0c7e48c374582fb851bb825fcc7249d404b99b9d7f1e1efc08265574aeac658d7b4a5be761cb8913614d0796aceb671b7c6865b8f18a1911e8e0d43c29ef496a99cbacc8333e4098a8a6dd7f0ea93f11189e73ca1d12aa8bd4a7b7c91e45ba8e8e9d36720f0dabeae813fc6d18479798b96b43071e7112a607dd9c086f9624abc5940f82b0a1e7b0dd21021fdd632d93bbc8e2b7869f66cd80a0ce2fe47ef63f5200be36a9aa8c9823314b1b40557582b3fb3e5b5c73c085d41ae7da6c8b54961bee3af02105eca20326427ab39d8c9326ebdd3c892e73c706ee621928adbe20b609d0846126ca012d931143e8e2244dac2050e02a388500ec12eef32453e19c9b8fc14c2224cd41d51eab7bd804cd0804fde774a461c0a437c358643927603e9beefb8d14c3736236462de6f72a7301697f9320e3762c8b79a3eec016d223678d366d94cbda6a7a2d2d40a5a55ad9d1d77c64bc9
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15879);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: NNTP");
 script_summary(english:"Brute force NNTP authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine NNTP passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find NNTP accounts and passwords by brute
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

 script_dependencies("hydra_options.nasl", "nntpserver_detect.nasl", "nntp_info.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/nntp");
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

port = get_service(svc:"nntp", exit_on_fail:TRUE);

if (get_kb_item("nntp/"+port+"/noauth")) exit(0, "The NNTP server listening on port "+port+" does not require authentication.");

# Check that the NNTP server is up & running
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv_line(socket: soc, length: 1024);
if (r !~ '^2[0-9][0-9] ') exit(0, "The banner from the NNTP server listening on port "+port+" is not 2xx.");

# Double check that authentication is not needed
ng="NoSuchGroup" + string(rand());
send(socket: soc, data: strcat('LIST ACTIVE ', ng, '\r\n'));
buff = recv_line(socket:soc, length:2048);
close(soc);
if ("480 " >< buff) exit(0, "The NNTP server listening on port "+port+" does not require authentication.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/nntp")) svc = "nntp";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'nntp' service.");
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
    set_kb_item(name: 'Hydra/nntp/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following NNTP credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the NNTP server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the NNTP server listening on port "+port+".");
