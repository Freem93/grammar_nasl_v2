#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65854);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/05/29 04:24:09 $");

  script_cve_id("CVE-2013-1902", "CVE-2013-1903");
  script_bugtraq_id(58877, 58882);
  script_osvdb_id(91958, 91959);

  script_name(english:"PostgreSQL 8.4 < 8.4.17 / 9.0 < 9.0.13 / 9.1 < 9.1.9 / 9.2 < 9.2.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PostgreSQL");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 8.4.x prior
to 8.4.17, 9.0.x prior to 9.0.13, 9.1.x prior to 9.1.9, or 9.2.x prior
to 9.2.4.  It therefore is potentially affected by multiple
vulnerabilities :

  - Enterprise DB's installers for Linux and Mac OS X create
    a directory and file in '/tmp' with predictable names.
    (CVE-2013-1902)

  - Enterprise DB's installers for Linux and Mac OS X pass
    the database superuser password to a script in an
    insecure fashion. (CVE-2013-1903)");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/about/news/1456/");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.4/static/release-8-4-17.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.0/static/release-9-0-13.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.1/static/release-9-1-9.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.2/static/release-9-2-4.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to PostgreSQL 8.4.17 / 9.0.13 / 9.1.9 / 9.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("postgresql_version.nbin", "os_fingerprint.nasl");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"postgresql", default:5432, exit_on_fail:TRUE);

os = get_kb_item_or_exit("Host/OS");
if ('Windows' >< os) audit(AUDIT_HOST_NOT, 'affected');

version = get_kb_item_or_exit('database/'+port+'/postgresql/version');
source = get_kb_item_or_exit('database/'+port+'/postgresql/source');

get_backport_banner(banner:source);
if (backported && report_paranoia < 2) audit(AUDIT_BACKPORT_SERVICE, port, 'PostgreSQL server');

ver = split(version, sep:'.');
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 8 && ver[1] == 4 && ver[2] < 17) ||
  (ver[0] == 9 && ver[1] == 0 && ver[2] < 13) ||
  (ver[0] == 9 && ver[1] == 1 && ver[2] < 9) ||
  (ver[0] == 9 && ver[1] == 2 && ver[2] < 4)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.4.17 / 9.0.13 / 9.1.9 / 9.2.4\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
