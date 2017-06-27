#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63350);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/29 04:24:09 $");

  script_cve_id("CVE-2010-3433");
  script_bugtraq_id(43747);
  script_osvdb_id(68436);

  script_name(english:"PostgreSQL 7.4 < 7.4.30 / 8.0 < 8.0.26 / 8.1 < 8.1.22 / 8.2 < 8.2.18 / 8.3 < 8.3.12 / 8.4 < 8.4.5 / 9.0 < 9.0.1");
  script_summary(english:"Checks version of PostgreSQL");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 7.4 prior to
7.4.30, 8.0 prior to 8.0.26, 8.1 prior to 8.1.22, 8.2 prior to 8.2.18,
8.3 prior to 8.3.12, 8.4 prior to 8.4.5, or 9.0 prior to 9.0.1.  It
therefore is potentially affected by a privilege escalation
vulnerability. 

A remote, authenticated attacker could elevate privileges via 
specially crafted code in a SECURITY DEFINER function.");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/about/news/1244/");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/7.4/static/release.html#RELEASE-7-4-30");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.0/static/release.html#RELEASE-8-0-26");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.1/static/release-8-1-22.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.2/static/release-8-2-18.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.3/static/release-8-3-12.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.4/static/release-8-4-5.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.0/static/release.html#RELEASE-9-0-1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 7.4.30 / 8.0.26 / 8.1.22 / 8.2.18 / 8.3.12 /
8.4.5 / 9.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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
  (ver[0] == 7 && ver[1] == 4 && ver[2] < 30) ||
  (ver[0] == 8 && ver[1] == 0 && ver[2] < 26) ||
  (ver[0] == 8 && ver[1] == 1 && ver[2] < 22) ||
  (ver[0] == 8 && ver[1] == 2 && ver[2] < 18) ||
  (ver[0] == 8 && ver[1] == 3 && ver[2] < 12) ||
  (ver[0] == 8 && ver[1] == 4 && ver[2] < 5) || 
  (ver[0] == 9 && ver[1] == 0 && ver[2] < 1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.4.30 / 8.0.26 / 8.1.22 / 8.2.18 / 8.3.12 / 8.4.5 / 9.0.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
