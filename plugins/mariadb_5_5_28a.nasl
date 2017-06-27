#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63150);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2012-5611"); # CVE-2012-5579 is a duplicate of this and shouldn't be used
  script_bugtraq_id(56769);
  script_osvdb_id(88060, 88066);
  script_xref(name:"EDB-ID", value:"23075");

  script_name(english:"MariaDB 5.5 < 5.5.28a Buffer Overflow");
  script_summary(english:"Checks MariaDB version");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB 5.5 running on the remote host is prior to
5.5.28a. It is, therefore, affected by a buffer overflow
vulnerability. A remote, authenticated attacker can exploit this to
execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Dec/4");
  script_set_attribute(attribute:"see_also", value:"https://kb.askmonty.org/en/mariadb-5528a-release-notes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to MariaDB version 5.5.28a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("audit.inc");
include("mysql_version.inc");

# mysql_check_version() can't be used since it thinks 5.5.28a < 5.5.28.
# since this has been the only mariadb release with a letter in the version,
# this plugin will workaround that issue instead of making a change in the library.
# the contents of this plugin are virtually the same as mysql_check_version() from
# mysql_version.inc. the main difference is noted by th ecomment below

variant = 'MariaDB';
fixed = '5.5.28a-MariaDB';
min = '5.5';
severity = SECURITY_WARNING;

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);
mysql_init(port:port, exit_on_fail:TRUE);
ver = mysql_get_version();
if (isnull(ver)) exit(1, 'Failed to get the version from the server listening on port '+port+'.');

sqlvar = mysql_get_variant();
if (variant != '')
{
  if (isnull(sqlvar)) exit(1, "Failed to determine the variant of the database service listening on port "+port+".");
  if (variant >!< sqlvar)
    exit(0, 'The database service listening on port '+port+' is not MariaDB.');
}

# Fix up MariaDB version.
real_ver = ver;
match = eregmatch(pattern:"^5\.5\.5-([0-9]+\.[0-9]+\.[0-9]+)-MariaDB", string:ver);
if (!isnull(match)) ver = match[1];

if (! isnull(min))
  if (mysql_ver_cmp(ver:ver, fix:min, same_branch:0) < 0 && ver != '5.5.28')
    exit(0, "The MariaDB "+ver+" server listening on port " + port + " is not affected.");

fixed = make_list(fixed);
br = (max_index(fixed) > 1);

foreach f (fixed)
{
  # this is the only difference from mysql_check_version() in mysql_version.inc
  # in addition to checking the range, 5.5.28 is explicitly checked as being vulnerable
  match = eregmatch(string:ver, pattern:'^((([0-9]+)\\.)+([0-9]+[a-z]*))');
  if (mysql_ver_cmp(ver:ver, fix:f, same_branch:br) < 0 || match[1] == '5.5.28')
  {
    report = NULL;
    if (report_verbosity > 0)
    {
      ver_ui = ver;
      if (ver != real_ver) ver_ui += " (" + real_ver + ")";

      report = "";
      if (variant != '') report += '\n  Variant           : ' + sqlvar;
      report += '\n  Installed version : ' + ver_ui +
                '\n  Fixed version     : ' + f + '\n';
    }

    security_report_v4(port:port, extra:report, severity:severity);
    exit(0);
  }
}
exit(0, "The MariaDB "+ver+" server listening on port " + port + " is not affected.");
