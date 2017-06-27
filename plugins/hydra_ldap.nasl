#TRUSTED 72bdc89c526ccdb341531bb26a8a653d0fb541936393c20143f1fec03aee60fcbd9979e9fabf4357e382ec8fe0470f06cb5a7379184d866961d023f9d63aa61d3bed46e08638689c57cf1723e9bf5d085f2a103d50fab3cba8c8e9a152b70d0bfdca93b37080c3717cbfa8ca18fde35be3df59e915729246e43abc6c19cc21f43ce57d6ec20fd3a25780ed7fe5b9624fe579ab8ef0c72aeed7749f9973a155418cbf4bc295a98744c8e5d2e4fdd9464376272e7b1e85bcb6ad25c55833a88af252d1ae444eda7d605753e3880d5be44771f4c551a7f54ac8938e712255438d6be7cf0de28d85c29880a459896ccd5c31693fbfca5c348332bead0bc0bb7fda63940fdfd654c3cd8e5ca755d96480aa3fa14116555d52241312770da4941c9a5c0616877c90065ac007821b447893be68d81b648343880eaa18a0976a6bd05fe89f9998684cada0dc4e0bac11899cfff0d4360511b1716ca3780cff46ec1de33917727b1a86b0436319efd50d821000f74b9b28f42960d64463788b60102f8127470ccdaf11dc999b0caeb3d8e5cce7cf94eeb2127fda39ca0686ad4145b581d86ee8442b8bc4c4e60984523b5d0c026f65bd846f6b02c7c56a7beb4498386be4ca60ef441909d230e158fea10224ad9e9dd3ca424480afe257ef2d2e7b94cb67e5f7b63386fe55fadea5f245734c6057cf25a544ca25f8a5e70ff7c27c59a51a
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15877);
 script_version("1.12");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: LDAP");
 script_summary(english:"Brute force LDAP authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine LDAP accounts through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find LDAP accounts and passwords by brute
force. 

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_add_preference(name: "DN : ", type: "entry", value: "");

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 # find_service does not detect LDAP yet, so we rely upon amap
 # However find_services will detect the SSL layer for LDAPS
 script_dependencies("hydra_options.nasl", "find_service1.nasl", "doublecheck_std_services.nasl", "external_svc_ident.nasl", "ldap_detect.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/ldap", 389);

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

dn = script_get_preference("DN : ");
if (! dn) exit(0, "No DN provided.");

port = get_service(svc:"ldap", exit_on_fail:TRUE);

# We should check that the server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/ldap")) svc = "ldap";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'ldap' service.");
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
argv[i++] = dn;

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
    set_kb_item(name: 'Hydra/ldap/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following LDAP credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the LDAP server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the LDAP server listening on port "+port+".");
