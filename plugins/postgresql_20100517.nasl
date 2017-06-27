#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63349);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2010-1169", "CVE-2010-1170", "CVE-2010-1975");
  script_bugtraq_id(40215, 40304);
  script_osvdb_id(64755, 64757, 64792);

  script_name(english:"PostgreSQL 7.4 < 7.4.29 / 8.0 < 8.0.25 / 8.1 < 8.1.21 / 8.2 < 8.2.17 / 8.3 < 8.3.11 / 8.4 < 8.4.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PostgreSQL");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 7.4 prior to
7.4.29, 8.0 prior to 8.0.25, 8.1 prior to 8.1.21, 8.2 prior to 8.2.17,
8.3 prior to 8.3.11 or 8.4 prior to 8.4.4.  As such, it is potentially
affected by multiple vulnerabilities :

  - A vulnerability in Safe.pm and PL/Perl can allow an
    authenticated user to run arbitrary Perl code on the
    database server if PL/Perl is installed and enabled.
    (CVE-2010-1169)

  - Insecure permissions on the pltcl_modules table could 
    allow an authenticated user to run arbitrary Tcl code
    on the database server if PL/Tcl is installed and 
    enabled. (CVE-2010-1170)

  - An unprivileged database user can remove superuser-only
    settings that were applied to the user's account with 
    ALTER USER by a superuser thus bypassing settings that 
    should be enforced. (CVE-2010-1975)");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/about/news/1203/");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/7.4/static/release-7-4-29.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.0/static/release-8-0-25.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.1/static/release-8-1-21.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.2/static/release-8-2-17.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.3/static/release-8-3-11.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.4/static/release-8-4-4.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 7.4.29 / 8.0.25 / 8.1.21 / 8.2.17 / 8.3.11 /
8.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/28");
  
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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
  (ver[0] == 7 && ver[1] == 4 && ver[2] < 29) ||
  (ver[0] == 8 && ver[1] == 0 && ver[2] < 25) ||
  (ver[0] == 8 && ver[1] == 1 && ver[2] < 21) ||
  (ver[0] == 8 && ver[1] == 2 && ver[2] < 17) ||
  (ver[0] == 8 && ver[1] == 3 && ver[2] < 11) ||
  (ver[0] == 8 && ver[1] == 4 && ver[2] < 4)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.4.29 / 8.0.25 / 8.1.21 / 8.2.17 / 8.3.11 / 8.4.4\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
