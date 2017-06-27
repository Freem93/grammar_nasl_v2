#TRUSTED 0732624eef0d532075774744a877081a463a269099195d0e81d1873f82866e7da3981384024ac4ebc16a01a1c97f17e76fa973ae4c594181960412f24c94323106a232b9fd27bbd8b613cfb659474ff1df5680eeab62a5c78585c6cdeb9fa1571f67953424f744fa776993508dd6c4a901ee526c64feebca24f6a56600b042a849d43a7108c33507416795418df5f850bc85f51ae5fd2381398a0fb396ff3c92856f186e9ee80473b64e3bb27e9cf05be8344d53c265295dc08193e4546f8995ae182cf19f04f0c58d9c5a7e9d62287ab4fa1ed57ec291f1cd14cc5f55f018e89666bb76f6b5d99b10483ba74ebfae2b33049c851048370a5f9f2346c963579ef568fdb1c90a1149f1041ac2e3ef68bb61d53fe027c70da5c3edaa2499e16e38d77675c306fb9c556140aafea206da85a3215777f2c9524236c0e862e42c6f323f4873477672d008369320ac77e03089ffa6e5811e6a51c77c8824ac96682cde111807fc89a8fd0d5f0bd24b29e2116fc257fc17ed4a89da3b5d1b4e4890318dd214d7f757fb390ccada4a05693e5831c74864cea204c2c0c17afc266017702d5d61e9b8879ea6679c520d0b8e2df8255366363384c4382c5f8d0131197a98e87ec1527215a226e5b6d98861140fa283b1fa22603977c3671646d8df1cbd68d592044439e6b0d630d6d27914ba9b38dbe1df4deec9e98f96792670e6012d07c0
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15880);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: PC-NFS");
 script_summary(english:"Brute force PC-NFS authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine PC-NFS passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find PC-NFS accounts and passwords by brute
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

 script_dependencies("hydra_options.nasl", "external_svc_ident.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_udp_ports(640);
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

port = get_service(svc:'pcnfs', ipproto:"udp", exit_on_fail:TRUE);      # port = 640?

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");

if (get_kb_item("/tmp/hydra/service/pcnfs")) svc = "pcnfs";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'pcnfs' service.");
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
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*)? password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/pcnfs/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, proto:"udp", extra:'\nHydra discovered the following PC-NFS credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the PC-NFS server listening on UDP port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the PC-NFS server listening on UDP port "+port+".");
