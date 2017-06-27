#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72659);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id(
    "CVE-2014-0060",
    "CVE-2014-0061",
    "CVE-2014-0062",
    "CVE-2014-0063",
    "CVE-2014-0064",
    "CVE-2014-0065",
    "CVE-2014-0066",
    "CVE-2014-2669"
  );
  script_bugtraq_id(
    65719,
    65723,
    65724,
    65725,
    65727,
    65728,
    65731,
    66557
  );
  script_osvdb_id(
    103544,
    103545,
    103546,
    103547,
    103548,
    103549,
    103551
  );

  script_name(english:"PostgreSQL 8.4 < 8.4.20 / 9.0 < 9.0.16 / 9.1 < 9.1.12 / 9.2 < 9.2.7 / 9.3 < 9.3.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PostgreSQL");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 8.4.x prior
to 8.4.20, 9.0.x prior to 9.0.16, 9.1.x prior to 9.1.12, 9.2.x prior to
9.2.7 or 9.3.x prior to 9.3.3.  It is, therefore, potentially affected
by multiple vulnerabilities :

  - SET ROLE bypasses lack of ADMIN OPTION when granting
    roles. (CVE-2014-0060)

  - It is possible to elevate privileges via calls to
    validator functions. (CVE-2014-0061)

  - It is possible to elevate privileges via a race
    condition in CREATE INDEX. (CVE-2014-0062)

  - Potential buffer overruns exist due to integer overflow
    in size calculations. (CVE-2014-0063)

  - Potential buffer overruns exist in datetime
    input/output. (CVE-2014-0064)

  - Multiple fixed-size buffers exist that could potentially
    be overflowed. (CVE-2014-0065)

  - A potential NULL pointer dereference crash is possible
    when crypt(3) returns NULL. (CVE-2014-0066)
    
  - Multiple integer overflow vulnerabilities exist in 
    'hstore_io.c' (CVE-2014-2669)");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/about/news/1506/");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/8.4/static/release-8-4-20.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.0/static/release-9-0-16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.1/static/release-9-1-12.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.2/static/release-9-2-7.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 8.4.17 / 9.0.13 / 9.1.9 / 9.2.4 / 9.3.3 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
  (ver[0] == 8 && ver[1] == 4 && ver[2] < 20) ||
  (ver[0] == 9 && ver[1] == 0 && ver[2] < 16) ||
  (ver[0] == 9 && ver[1] == 1 && ver[2] < 12) ||
  (ver[0] == 9 && ver[1] == 2 && ver[2] < 7) ||
  (ver[0] == 9 && ver[1] == 3 && ver[2] < 3)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.4.20 / 9.0.16 / 9.1.12 / 9.2.7 / 9.3.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
