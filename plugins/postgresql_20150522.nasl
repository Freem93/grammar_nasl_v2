#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83818);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id(
    "CVE-2015-3165",
    "CVE-2015-3166",
    "CVE-2015-3167"
  );
  script_bugtraq_id(
    74787,
    74789,
    74790
  );
  script_osvdb_id(
    122456,
    122457,
    122458);

  script_name(english:"PostgreSQL 9.0 < 9.0.20 / 9.1 < 9.1.16 / 9.2 < 9.2.11 / 9.3 < 9.3.7 / 9.4 < 9.4.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PostgreSQL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 9.0.x prior
to 9.0.20, 9.1.x prior to 9.1.16, 9.2.x prior to 9.2.11, 9.3.x prior
to 9.3.7, or 9.4.x prior to 9.4.2. It is, therefore, affected by
multiple vulnerabilities :

  - A double free memory error exists after authentication
    timeout, which a remote attacker can utilize to cause
    the program to crash. (CVE-2015-3165)

  - A flaw exists in the printf() functions due to a failure
    to check for errors. A remote attacker can use this to
    gain access to sensitive information. (CVE-2015-3166)

  - pgcrypto has multiple error messages for decryption
    with an incorrect key. A remote attacker can use this
    to recover keys from other systems. (CVE-2015-3167)");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/about/news/1587/");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.0/static/release-9-0-20.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.1/static/release-9-1-16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.2/static/release-9-2-11.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.3/static/release-9-3-7.html");
  script_set_attribute(attribute:"see_also", value:"http://www.postgresql.org/docs/9.4/static/release-9-4-2.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 9.0.20 / 9.1.16 / 9.2.11 / 9.3.7 / 9.4.2 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/27");

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
  (ver[0] == 9 && ver[1] == 0 && ver[2] < 20) ||
  (ver[0] == 9 && ver[1] == 1 && ver[2] < 16) ||
  (ver[0] == 9 && ver[1] == 2 && ver[2] < 11) ||
  (ver[0] == 9 && ver[1] == 3 && ver[2] < 7) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] < 2)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.0.20 / 9.1.16 / 9.2.11 / 9.3.7 / 9.4.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
