#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93006);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/08/18 13:36:11 $");

  script_cve_id("CVE-2015-6817");
  script_osvdb_id(127284);

  script_name(english:"Pgbouncer 1.6 Invalid User Authentication Bypass");
  script_summary(english:"Attempts to log in through Pgbouncer using a random user name.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database connection pooler is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Pgbouncer running on the remote host is affected by an
authentication bypass vulnerability due to a flaw in the
start_auth_request() function within file client.c when handling
requests for invalid users. A remote attacker can exploit this issue
to bypass authentication and log into PostgreSQL via Pgbouncer using a
random user name.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2015/q3/495");
  script_set_attribute(attribute:"see_also", value:"https://github.com/pgbouncer/pgbouncer/issues/69");
  # https://web.archive.org/web/20150911232806/http://comments.gmane.org/gmane.comp.db.postgresql.pgbouncer.general/1251
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?342233a3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pgbouncer version 1.6.1 or later. Alternatively, disable
'auth_user' in the Pgbouncer configuration.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:pgbouncer:pgbouncer");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("pgbouncer_detect.nbin");
  script_require_ports("Services/pgbouncer", 5432, 6432);
  script_exclude_keys("global_settings/supplied_logins_only");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("pgbouncer_func.inc");

app = 'pgbouncer';
port = get_service(svc:"pgbouncer", exit_on_fail:TRUE);

if (!get_port_state(port)) audit(AUDIT_NOT_LISTEN, app, port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = rand_str(length:16); # generate random user name
res = pgbouncer_login(port:port, user:user, database:'postgres');

# look for indication of successful login
if (!empty_or_null(res) &&
    "server_version" >< res &&
    "is_superuser" >< res &&
    "application_name" >< res
  )
{
  report =
    '\n  Nessus was able to log into PostgreSQL via Pgbouncer using' +
    '\n  the following randomly generated user name:' +
    '\n    ' + user;
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port);
