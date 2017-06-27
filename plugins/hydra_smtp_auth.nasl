#TRUSTED 23e5ca748c1201ef00373b519bb06cc754b61536fee2fbce87d72fdb17edaa93287650914cb766a0b21415380b3f1f050f639343aac175283b0d2a8d3cfcd0705851180be992a3f3c91926647b297fe89219e5c09c8f3d7590abf7cdcf50676cf00052badb29c45bdf7189cdc40e2c51779e10bba895bf9ff1b743c5f8ec20ebf16cf2d3ade928f1c0f0ff06b2dbf5053534efa3980620e78a80b96797014b856317e33e6665c069f6fa324b942d8af42408b1d01df12a735dd4d90da66613315b848076984f071d0c44c6f3467800b09cecb3b197f579b1c06d8fda3d6817521b31f519d3416bf3c72cb35e49fb9fa67fb138fcc907657447fd7a196b4f67c7fb40887b35aac060346a98cd32fffebde4e0f35d2aba075537e293b16cd132c12f4ffcd6155f288d72951a9c13913d4a53f4d97d840ff61d499e636cf7d250f5f2d88deb0f7d42c306410f98550fca0194b65e830c48f260f0f66be56b72f605365ba7ad5fd517125c1c7a2af1a414532f793efe78df12deb7a76516604e324a676ae774be1b8ac7e8e4718182914a1e0f62d6f32329391979ac2359a8fdd673c05c3bf4d015908f0dabb651fe194b8bf2d89b828a7dca9ad71e11fdceaacc961f9eef0edde8e225e4c9325eaf299c8741625fc34ef62cda09199f632a9d5b3f7f63f393a0efc2e78abfc0078feb376c39867d725b3bdbad00b6cd07b862d125
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15885);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: SMTP AUTH");
 script_summary(english:"Brute force SMTP AUTH authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SMTP AUTH passwords through brute 
force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SMTP AUTH accounts and passwords by
brute force. 

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

 script_dependencies("hydra_options.nasl", "smtpserver_detect.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/smtp");
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

port = get_service(svc:"smtp", exit_on_fail:TRUE);          # port = 25?
# NB: Hydra will exit if SMTP AUTH is not enabled

# Check that the MTA is up & running
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

r = recv_line(socket: soc, length: 1024);
close(soc);
if (r !~ '^2[0-9][0-9] ') exit(1, "The banner from the SMTP server listening on port "+port+" indicates a problem.");
# Here we could send a EHLO & check that AUTH is supported...

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/smtp-auth")) svc = "smtp-auth";
else if (get_kb_item("/tmp/hydra/service/smtp")) svc = "smtp";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'smtp-auth' or 'smtp' services.");
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

set_kb_item(name:"Hydra/smtp/"+port+"/cmd_line", value:join(argv));

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
    set_kb_item(name: 'Hydra/smtp/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following SMTP credentials :\n\n' + report);

if (max_index(errors) > 0)
{
  msg = '';
  n = 0;
  foreach error (list_uniq(errors))
  {
    n++;
    if (n < 20) msg = strcat(msg, error, '\n');
  }

  set_kb_item(name:"Hydra/errors/smtp/"+port, value:n);
  set_kb_item(name:"Hydra/error_msg/smtp/"+port, value:msg);

  exit(1, "One or more errors occurred while running Hydra against the SMTP server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the SMTP server listening on port "+port+".");
