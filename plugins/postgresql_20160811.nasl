#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93050);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/19 14:17:02 $");

  script_cve_id("CVE-2016-5423", "CVE-2016-5424");
  script_bugtraq_id(92433, 92435);
  script_osvdb_id(142811, 142826, 143018, 143019);
  
  script_name(english:"PostgreSQL 9.1.x < 9.1.23 / 9.2.x < 9.2.18 / 9.3.x < 9.3.14 / 9.4.x < 9.4.9 / 9.5.x < 9.5.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PostgreSQL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.1.x prior
to 9.1.23, 9.2.x prior to 9.2.18, 9.3.x prior to 9.3.14, 9.4.x prior
to 9.4.9, or 9.5.x prior to 9.5.4. It is, therefore, affected by the
following vulnerabilities :

  - A denial of service vulnerability exists that allows an
    authenticated, remote attacker to crash the database via
    specially crafted nested CASE expressions.
    (CVE-2016-5423)

  - A flaw exists that is triggered during the handling of
    database and role names with embedded special
    characters. An unauthenticated, remote attacker can
    exploit this to execute arbitrary code during
    administrative operations such as pg_dumpall.
    (CVE-2016-5424)

  - A denial of service vulnerability exists in the
    pg_get_expr() function that is triggered during the
    handling of inconsistent values. An authenticated,
    remote attacker can exploit this to crash the database.
    (VulnDB 143018)

  - An overflow condition exists in the to_number() function
    due to improper validation of user-supplied input. An
    authenticated, remote attacker can exploit this to cause
    a denial of service condition. (VulnDB 143019)");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/about/news/1688/");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/current/static/release-9-1-23.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/current/static/release-9-2-18.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/current/static/release-9-3-14.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/current/static/release-9-4-9.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/current/static/release-9-5-4.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL version 9.1.23 / 9.2.18 / 9.3.14 / 9.4.9 / 9.5.4
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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
  (ver[0] == 9 && ver[1] == 1 && ver[2] < 23) ||
  (ver[0] == 9 && ver[1] == 2 && ver[2] < 18) ||
  (ver[0] == 9 && ver[1] == 3 && ver[2] < 14) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] < 9) ||
  (ver[0] == 9 && ver[1] == 5 && ver[2] < 4)
)
{
  order = make_list("Version source", "Installed version", "Fixed version");
  report = make_array(
    order[0], source,
    order[1], version,
    order[2], "9.1.23 / 9.2.18 / 9.3.14 / 9.4.9 / 9.5.4"
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
