#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63351);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/29 04:24:09 $");

  script_cve_id("CVE-2010-4015");
  script_bugtraq_id(46084);
  script_osvdb_id(70740);

  script_name(english:"PostgreSQL 8.2 < 8.2.20 / 8.3 < 8.3.14 / 8.4 < 8.4.7 / 9.0 < 9.0.3 Buffer Overflow Vulnerability");
  script_summary(english:"Checks version of PostgreSQL");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 8.2.x prior
to 8.2.20, 8.3.x prior to 8.3.14, 8.4.x prior to 8.4.7, or 9.0.x prior
to 9.0.3.  It therefore is potentially affected by a buffer overflow
vulnerability. 

By calling functions from the intarray optional module with certain
parameters, a remote, authenticated attacker could execute arbitrary
code on the remote host subject to the privileges of the user running
the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/about/news/1289/");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.2/static/release-8-2-20.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.3/static/release-8-3-14.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.4/static/release-8-4-7.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.0/static/release-9-0-3.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to PostgreSQL 8.2.20 / 8.3.14 / 8.4.7 / 9.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/31");
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
  (ver[0] == 8 && ver[1] == 2 && ver[2] < 20) ||
  (ver[0] == 8 && ver[1] == 3 && ver[2] < 14) ||
  (ver[0] == 8 && ver[1] == 4 && ver[2] < 7) || 
  (ver[0] == 9 && ver[1] == 0 && ver[2] < 3)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.2.20 / 8.3.14 / 8.4.7 / 9.0.3\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
