#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86422);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id("CVE-2015-5288", "CVE-2015-5289");
  script_osvdb_id(
    128634,
    128635,
    129228,
    129229,
    129230,
    129231
  );

  script_name(english:"PostgreSQL 9.0.x < 9.0.23 / 9.1.x < 9.1.19 / 9.2.x < 9.2.14 / 9.3.x < 9.3.10 / 9.4.x < 9.4.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PostgreSQL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.0.x prior
to 9.0.23, 9.1.x prior to 9.1.19, 9.2.x prior to 9.2.14, 9.3.x prior
to 9.3.10, or 9.4.x prior to 9.4.5. It is, therefore, affected by
multiple vulnerabilities :

  - A denial of service vulnerability exists due to an
    unspecified flaw in the crypt() function. An
    authenticated, remote attacker can exploit this to cause
    a memory leak, resulting in a denial of service
    condition. (CVE-2015-5288)

  - A denial of service vulnerability exists due to improper
    validation of user-supplied JSON input. An
    authenticated, remote attacker can exploit this, via
    specially crafted JSON input, to cause the server to
    crash. (CVE-2015-5289)

  - A denial of service vulnerability exists due to a flaw
    that is triggered when a function is executed in an
    outer-subtransaction cursor. An authenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (VulnDB 129228)

  - Multiple stack overflow conditions exist due to improper
    validation of user-supplied input when handling input to
    record types, range types, json, jsonb, tsquery,
    ltxtquery and query_int. An authenticated, remote
    attacker can exploit this to cause a denial of service
    condition and potentially remote code execution.
    (VulnDB 129229)

  - An information disclosure vulnerability exists due to
    world-readable permissions granted to temporary files
    that are created during a pg_dump with tar-format
    output. A local attacker can exploit this disclose
    sensitive information. (VulnDB 129230)

  - An overflow condition exists due to improper validation
    of user-supplied input when handling SIMILAR TO and LIKE
    matching regular expressions. An authenticated, remote
    attacker can exploit this to cause a stack overflow,
    resulting in a denial of service condition.
    (VulnDB 129231)");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/about/news/1615/");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.0/static/release-9-0-23.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.1/static/release-9-1-19.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.2/static/release-9-2-14.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.3/static/release-9-3-10.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.4/static/release-9-4-5.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 9.0.23 / 9.1.19 / 9.2.14 / 9.3.10 / 9.4.5 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
  (ver[0] == 9 && ver[1] == 0 && ver[2] < 23) ||
  (ver[0] == 9 && ver[1] == 1 && ver[2] < 19) ||
  (ver[0] == 9 && ver[1] == 2 && ver[2] < 14) ||
  (ver[0] == 9 && ver[1] == 3 && ver[2] < 10) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] < 5)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.0.23 / 9.1.19 / 9.2.14 / 9.3.10 / 9.4.5\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
