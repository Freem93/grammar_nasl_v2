#TRUSTED af924d8bdb5b7cd245d70f85de81b5abd020fd4f4282bf3cf5947dbb6ca91af5a40aac1c74559fd3f204992f9604d1995d16835558c6ae6fe1be86a44ccc6c54f9a3263926ef8045394baf7ed844ce45117c7014cf7fc62bc11e81e1377c92e8f5cba2507d50052393189cd8433229334cd67ef2854eb6628d4ec52c3249b041457bc867075c62751f8ef8730bdde84be4cc9ecadba87abd557a128016ee29f1affb9656ef971fb3ff96fb6a70b9c25832cc4c0e8116b28d8496c0d273b2df6cc1e66ed07c9c3ad668541081db36c59f16665504b651e8afb60e9184ff6bf9cfc7cd50cd9dd9ebb7994996d66257266bcde348b6435073cac08d7e36a174fcbb1b440fee6f62de1f1c86b2e7e6aa833623a240285b2090dc2a78e3eec0fdea1e0ed93397291d64aa9332e48e5d010e0f8653cc1014cf5cfef9a3948d2d41cf1787a692169604ffdd1b93914c1276d4d343613818e7bff0cb40f47acd59f0e160075dfd64c54166b1d94274ad3c657089bfde406dc513edab015e3781548f5e887458b9946e65236208de27afae19a6746843ecf2b1aa71a708d354a90042db19448fa856363690e0d9fb87530798500aa4affb66a89c7cb434a13b036d6fac4bc37a7e9fe759d0358d663eb0ba3a4c39a8e830e763cc0edb993ca377f746ab0f5b5befb1efb5e99a33fbbec717bdcb513b348a9b88eb115f9eb7e1a33569318a
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(18661);
 script_version("1.8");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: MySQL");
 script_summary(english:"Brute force MySQL authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine MySQL passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find MySQL accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/10");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl", "mysql_version.nasl", "mysql_unpassworded.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/mysql");
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

port = get_service(svc:"mysql", exit_on_fail:TRUE);

if (get_kb_item('MySQL/no_passwd/'+port)) exit(0, "The MySQL server listening on port "+port+" does not have a password.");

# We should check that the server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/mysql")) svc = "mysql";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'mysql' service.");
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
  v = eregmatch(string: line, pattern: 'host:.*login: *(.*) password: *(.*)$');
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'login: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'Hydra/mysql/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following MySQL credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the MySQL server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the MySQL server listening on port "+port+".");
