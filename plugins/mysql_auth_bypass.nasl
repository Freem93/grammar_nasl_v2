#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61393);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id("CVE-2012-2122");
  script_bugtraq_id(53911);
  script_osvdb_id(82804);
  script_xref(name:"EDB-ID", value:"19092");

  script_name(english:"MySQL Authentication Protocol Token Comparison Casting Failure Password Bypass");
  script_summary(english:"Checks for an authentication bypass in MySQL");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server can be accessed without a valid
password.");
  script_set_attribute(attribute:"description", value:
"A flaw in the MySQL server allows remote users to authenticate
without a valid password due to a failure when casting a randomly
generated token and comparing it to an expected value.");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL 5.1.63 / 5.5.24 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2012/q2/493");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=64884");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/mysql", 3306);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");

function show_databases()
{
  local_var db, dbs, res;

  mysql_send_packet(data:mkbyte(3) + "show databases", num:0);

  res = mysql_recv_packet();
  if (isnull(res) || res["num"] != 1)
    return NULL;

  res = mysql_recv_packet();
  if (isnull(res))
    return NULL;

  res = mysql_recv_packet();
  if (isnull(res) || getbyte(blob:res["data"], pos:0) != 254)
    return NULL;

  dbs = make_list();
  while (TRUE)
  {
    res = mysql_recv_packet();
    if (isnull(res) || getbyte(blob:res["data"], pos:0) == 254)
      break;

    db = substr(res["data"], 1, res["len"] - 1);
    dbs = make_list(dbs, db);
  }

  if (max_index(dbs) <= 0)
    return NULL;

  return dbs;
}

app = "MySQL";

port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

if (supplied_logins_only)
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Try up to 1000 times (there's a 1/256 chance of it happening each time).
max_attempts = 1000;

# Because of the number of connections, occasional failures happen. To
# combat that, we let a few consecutive failures slip past before
# giving up.
max_failures = 3;
failures = 0;

# Track what we've observed so that we can accurately report our
# findings.
vulnerable = FALSE;
connected = FALSE;
databases = NULL;

# Generate a random password for our login attempts that is unlikely
# to match the root account's password.
nonce = SCRIPT_NAME + "-" +  unixtime();

for (i = 0; i < max_attempts && failures < max_failures && !vulnerable; i++)
{
  # Initialize a session with the server.
  if (mysql_init(port:port, nocache:TRUE) != 1)
  {
    failures++;
    continue;
  }

  # Reset the number of consecutive failures and remember that we
  # successfully connected.
  connected = TRUE;
  failures = 0;

  # Get the server's capabilities.
  caps = mysql_get_caps();
  caps = caps & (0xFFFFFFFF - CLIENT_NO_SCHEMA);

  # Attempt logging in.
  if (mysql_login(user:"root", pass:nonce, db:"mysql", flags:caps) == 1)
  {
    databases = show_databases();
    vulnerable = TRUE;
  }

  # Tear down the session.
  mysql_close();
}

# Check for all the things that may have gone wrong.
if (!connected)
  exit(1, "Could not confirm that the server on port " + port + " is MySQL: repeated failures connecting.");

if (failures >= max_failures)
  exit(1, "Could not determine if the MySQL server on port " + port + " is affected: too many failures.");

if (!vulnerable) audit(AUDIT_LISTEN_NOT_VULN, app, port);

# Report our findings.
report = NULL;
if (report_verbosity > 0 && !isnull(databases))
{
  report =
    '\nHere is the list of databases on the remote server :' +
    '\n' +
    '\n  ' + join(sort(databases), sep:'\n  ') +
    '\n';
}

security_hole(port:port, extra:report);
