#TRUSTED 3188a1a4e7eb02bc7aeea4d56efee33a3bd03692b4070ada12f32fd908781f6f0c943c0da6c7d4e960ef6a6a0cc3c6c072cee3beb405cffac53bbd2071afb67c378436d03f57d101d18a8d01e5cc61460125aea1d9aecb5a6f7c8a0ae723b431d87c60a0c222fdc2a89f8db73dcdad4a7a44ef6ef4fe75468cc803da736d2f9195e48199bbded15c38843727e692abe74cce436ae4328ec29ac98818eb5fddc46f9fc59d24307a5de6d36145c702e0bf36c3c51a91505979156ba38103eb22716e50a0ad2295f2ebf168c9075aefdf357b72e012ff038665e0e7c873a4639100026d099275221b6fdb6e4c84c4717cbd48382974d048e7859674de92b4c47eb76413773f75a61b558d82f04ddba68c1d3fdd5d1f2efabe2059ce399c7e7c8889ad155dc2fb438272e83466b4f7992ad2c9b86b77d3f91aec424e15cc0716ae7e508188a7993fe82db6118fcdbf8e9531dd617cac302a22132f2a9dda56476dfdb5d5d2cdac52d1df89caf5192cabb9315b5f42bf17f1cae2ccb8ae52d5958517c32d7e32b9eee26a11b950da772217540c688f08b9af3a0684e054026abef0232f03379e63cbcc61d16f1ac7cd62000b92c2ab52fa16a55d3a2fd1c235f351065f11134c2f3132f52af7bcd0d87ffa2e765a8d12c7c2262006fa243a3b908bff5eef502f5e41bddbf84db8eb2a76c2e63654707661e0acfc59f426090dfa4d78
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(15871);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/07/27");

 script_name(english:"Hydra: CVS");
 script_summary(english:"Brute force CVS authentication with Hydra");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine CVS passwords through brute force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find CVS accounts and passwords by brute
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

 script_dependencies("hydra_options.nasl", "find_service1.nasl", "cvs_detect.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/cvspserver", 2401);
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

port = get_service(svc:"cvspserver", exit_on_fail:TRUE);       # port = 2401?

# We should check that the server is up & running

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/cvs")) svc = "cvs";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'cvs' service.");
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
 exit(0, "No Hydra password file");

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
    set_kb_item(name: 'Hydra/cvs/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following CVS credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the CVS service listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the CVS service listening on port "+port+".");
