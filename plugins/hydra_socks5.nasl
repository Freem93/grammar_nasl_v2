#TRUSTED 2088d01a681bb9d7bf9d9c8b448b87ffab2cdc798e42b4ad93df98ba43a384d678dec07c8ccf787ecb4970727128166b924e885c893aa08a833e88bb27b34ee920620f45bf2f4f0d3da1f64a98e47649861ef6f86ccdb1c897b68e3fd0b35218c5f08ff4bfb0753d2bff9269d8c598343c3e1a5f5d1513047b5acfd94c0503331675bf2f63c3bb8bac4a8da668315dfaebae351c2bd7917c896dca3414f77c6f83914a82e9279f724cb1856375c7f9076b38d34235a1665a29d165c283364fa427f2fc86951ac9c410088285fbbb38e4500d074533a9a0e2bddb3e1d0ec15f492f08db5489f5e415b9578e6c1beef7dc3eadbdbf2d5e3a9cfaf65e6fe7b1359949d6fd0b313d5d46589ce8cabe43aefc367890ea1871f161a92c9909166cdf1cbcebaa36b8fbd980077eac9782a6c7f6287edc105f8d5163c29d8793f6a3b200586bbcfc216a73a9b107d0143960788af1ce77983c7b73eedb2a8644d3a171ba1277997d7273205d2c08a1f583ce9b0720d3f147ae1b6b5eef4b7bd605b7e30e45132813fabe957c274edbfe602f3e5068a66da357d6c464ac2d886ea1e4a87eb6f07348c7ef3ff0e91e0583baa888b98f9c13a159a5e295b42bdb93b3aacffcf385c639858a90decc5d0efe6dbebbc57cd858d0a1097b768a8e2b388147a3763770df547829a5d79d193117024376735cc27aaace4ca00f1f9414261a030c33
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15887);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: SOCKS5");
 script_summary(english:"Brute force SOCKS5 authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine SOCKS5 passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find SOCKS5 accounts and passwords by brute
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

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "socks.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/socks5");
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

port = get_service(svc:"socks5", exit_on_fail:TRUE);

if (!get_kb_item("socks5/auth/"+port)) exit(0, "The SOCKS5 server on port "+port+ " is not password-protected.");	# Not authentication is required

# TBD: check that the SOCKS server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/socks5")) svc = "socks5";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'socks5' service.");
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
}
else if (!s)
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
    set_kb_item(name: 'Hydra/socks5/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following SOCKS5 credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the SOCKS5 server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the SOCKS5 server listening on port "+port+".");
