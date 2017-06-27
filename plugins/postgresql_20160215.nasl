#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88808);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/29 19:06:13 $");

  script_cve_id("CVE-2016-0773", "CVE-2016-0766");
  script_osvdb_id(134458, 134459);

  script_name(english:"PostgreSQL 9.1.x < 9.1.20 / 9.2.x < 9.2.15 / 9.3.x < 9.3.11 / 9.4.x < 9.4.6 / 9.5.x < 9.5.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PostgreSQL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.1.x prior
to 9.1.20, 9.2.x prior to 9.2.15, 9.3.x prior to 9.3.11, 9.4.x prior
to 9.4.6, or 9.5.x prior to 9.5.1. It is, therefore, affected by the
following vulnerabilities :

  - An integer overflow condition exists due to improper
    validation of user-supplied input when handling regular
    expressions. An authenticated, remote attacker can
    exploit this, via a large Unicode character range in a
    regular expression, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-0773)

  - A privilege escalation vulnerability exists due to a
    flaw in the init_custom_variable() function that is
    triggered during the handling of PL/Java. An
    authenticated, remote attacker can exploit this to gain
    elevation privileges. (CVE-2016-0766)");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/about/news/1644/");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/current/static/release-9-1-20.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/current/static/release-9-2-15.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/current/static/release-9-3-11.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/current/static/release-9-4-6.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/current/static/release-9-5-1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL version 9.1.20 / 9.2.15 / 9.3.11 / 9.4.6 / 9.5.1
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"postgresql", default:5432, exit_on_fail:TRUE);

version = get_kb_item_or_exit('database/'+port+'/postgresql/version');
source = get_kb_item_or_exit('database/'+port+'/postgresql/source');

get_backport_banner(banner:source);
if (backported && report_paranoia < 2) audit(AUDIT_BACKPORT_SERVICE, port, 'PostgreSQL server');

ver = split(version, sep:'.');
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 9 && ver[1] == 1 && ver[2] < 20) ||
  (ver[0] == 9 && ver[1] == 2 && ver[2] < 15) ||
  (ver[0] == 9 && ver[1] == 3 && ver[2] < 11) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] < 6) ||
  (ver[0] == 9 && ver[1] == 5 && ver[2] < 1)
)
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 9.1.20 / 9.2.15 / 9.3.11 / 9.4.6 / 9.5.1\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
