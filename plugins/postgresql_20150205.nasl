#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81300);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id(
    "CVE-2014-0067",
    "CVE-2014-8161",
    "CVE-2015-0241",
    "CVE-2015-0242",
    "CVE-2015-0243",
    "CVE-2015-0244"
  );
  script_bugtraq_id(
    65721,
    72538,
    72540,
    72542,
    72543,
    74174
  );
  script_osvdb_id(
    103550,
    118033,
    118034,
    118035,
    118036,
    118037,
    118038
  );

  script_name(english:"PostgreSQL 9.0 < 9.0.19 / 9.1 < 9.1.15 / 9.2 < 9.2.10 / 9.3 < 9.3.6 / 9.4 < 9.4.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PostgreSQL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.0.x prior
to 9.0.19, 9.1.x prior to 9.1.15, 9.2.x prior to 9.2.10, 9.3.x prior
to 9.3.6, or 9.4.x prior to 9.4.1. It is, therefore, affected by
multiple vulnerabilities :

  - A privilege escalation vulnerability exists due to the
    'make check' command not properly invoking initdb to
    specify authentication requirements for a database
    cluster to be used for tests. A local attacker can
    exploit this issue to gain temporary server access and
    elevated privileges. Note that this issue only affects
    Microsoft Windows hosts. (CVE-2014-0067)

  - An information disclosure vulnerability exists due to
    improper handling of restricted column values in
    constraint-violation error messages. An authenticated,
    remote attacker can exploit this to gain access to
    sensitive information. (CVE-2014-8161)

  - Multiple vulnerabilities exist due to several buffer
    overflow errors related to the 'to_char' functions. An
    authenticated, remote attacker can exploit these issues
    to cause a denial of service or arbitrary code
    execution. (CVE-2015-0241)

  - Multiple vulnerabilities exist due to several
    stack-based buffer overflow errors in various *printf()
    functions. The overflows are due to improper validation
    of user-supplied input when formatting a floating point
    number where the requested precision is greater than
    approximately 500. An authenticated, remote attacker
    can exploit these issues to cause a denial of service or
    arbitrary code execution. (CVE-2015-0242)

  - Multiple vulnerabilities exist due to an overflow
    condition in multiple functions in the 'pgcrypto'
    extension. The overflows are due to improper validation
    of user-supplied input when tracking memory sizes. An
    authenticated, remote attacker can exploit these issues
    to cause a denial of service or arbitrary code
    execution. (CVE-2015-0243)

  - A SQL injection vulnerability exists due to improper
    sanitization of user-supplied input when handling
    crafted binary data within a command parameter. An
    authenticated, remote attacker can exploit this issue
    to inject or manipulate SQL queries, allowing the
    manipulation or disclosure of arbitrary data.
    (CVE-2015-0244)");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/about/news/1569/");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.0/static/release-9-0-19.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.1/static/release-9-1-15.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.2/static/release-9-2-10.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.3/static/release-9-3-6.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.4/static/release-9-4-1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 9.0.19 / 9.1.15 / 9.2.10 / 9.3.6 / 9.4.1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/11");

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
  (ver[0] == 9 && ver[1] == 0 && ver[2] < 19) ||
  (ver[0] == 9 && ver[1] == 1 && ver[2] < 15) ||
  (ver[0] == 9 && ver[1] == 2 && ver[2] < 10) ||
  (ver[0] == 9 && ver[1] == 3 && ver[2] < 6) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] < 1)
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.0.19 / 9.1.15 / 9.2.10 / 9.3.6 / 9.4.1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
