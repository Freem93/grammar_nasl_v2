#TRUSTED 2f678a7ba004fba7e06474b04647cd3f6c541467d8c2247503c27ee18fc8e7289437345668f7cb9fb690fc091999a7cfe5940c04c55fcc8f77bd5771f6de3e57346000b731804fdfdfd8a94f0ceb9fcbdc41e1048da3775813aa37b37d00e477248a6588291a816939f058b110887941b313e8b74e128470fa5cb15839f20b449759863f0bf7e37004b7bfb25eeca9298a64e990c64cb6acad35920996afd5fbc10ee3b6d5b5a28e69707d483f03595a5a368c3af00563a090f1f5e7f52a1955b8baae36cffd449e690029df0aa409e0a25ec3b9dd4f67bf541fb075dfb10f7779cedca6e1aeee8ae609481b5a558111e4c2c7baf2a998414caf2a926f13593e503351eb166c5b294f557b188b09d575096105c200904bb4f56493e34e134004a0a0e3485ced003e2611e0a9bf2f7a51d70038a60cebaf211961ab6b3b13cf01c0d72eb69e96436c2e8a289e3a92b02aa6de5fb2efc40bd34ebbb1c71e08e1abd6aa3c343144625e9d30860a143b258e0384d37f9dbb8ddf34143cda495253428678556c0142cc6f2f68098a9dca048beec64cc24aa514ae8d87205df9d5d26a6e600be0686e4bb5a7b4a1f56be33682c62b0c6136a2445f17d1685f1731a44150e9ae3b9831865e95626043dac956b32d16ef80afee2526a524bc43e555ee581ad789bfc9d4843dd73a9013267d5f6051bc7e1549b612001ab1eb83ee5f56cd
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("script_get_preference_file_location")) exit(0);
if (!find_in_path("hydra")) exit(0, "Hydra was not found in '$PATH'.");

include("compat.inc");

if (description)
{
 script_id(18660);
 script_version("1.9");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/10/06");

 script_name(english:"Hydra: PostgreSQL");
 script_summary(english:"Brute force PostgreSQL authentication with Hydra");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to determine PostgreSQL passwords through brute
force.");
 script_set_attribute(attribute:"description", value:
"This plugin runs Hydra to find PostgreSQL accounts and passwords by
brute force.

To use this plugin, enter the 'Logins file' and the 'Passwords file'
under the 'Hydra (NASL wrappers options)' advanced settings block.");
 script_set_attribute(attribute:"solution", value:"Change the passwords for the affected accounts.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_add_preference(name: "Database name (optional) : ", type: "entry", value: "");

 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_dependencies("hydra_options.nasl", "postgresql_detect.nasl", "doublecheck_std_services.nasl", "postgresql_unpassworded.nasl");
 script_require_keys("Secret/hydra/logins_file", "Secret/hydra/passwords_file", "/tmp/hydra/force_run");
 script_require_ports("Services/postgresql", 5432);

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

port = get_service(svc:"postgres", exit_on_fail:TRUE);      # port = 5432?

if (get_kb_item('postgresql/no_pass/'+port)) exit(0, "The PostgreSQL server listening on port "+port+" is not password protected.");

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
login_pass = get_kb_item("/tmp/hydra/login_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

if (get_kb_item("/tmp/hydra/service/postgres")) svc = "postgres";
else if (get_kb_item("Hydra/services")) exit(1, "The installed version of Hydra does not support the 'postgres' service.");
else exit(1, "Failed to get the list of services that the installed version of Hydra supports.");

db = script_get_preference("Database name (optional) : ");

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
if (db) argv[i++] = db;

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
    set_kb_item(name: 'Hydra/postgres/'+port, value: l + '\t' + p);
  }
  else if (line =~ "^(Error: |Sorry, hydra)")
  {
    errors = make_list(errors, line);
  }
}

if (report) security_hole(port:port, extra:'\nHydra discovered the following PostgreSQL credentials :\n\n' + report);

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

  exit(1, "One or more errors occurred while running Hydra against the PostgreSQL server listening on port "+port+".");
}

if (!report) exit(0, "Hydra did not discover any credentials for the PostgreSQL server listening on port "+port+".");
