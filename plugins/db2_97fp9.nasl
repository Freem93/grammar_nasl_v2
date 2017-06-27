#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71519);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/16 21:08:26 $");

  script_cve_id(
    "CVE-2012-2190",
    "CVE-2012-2191",
    "CVE-2012-2203",
    "CVE-2013-3475",
    "CVE-2013-4033",
    "CVE-2013-5466",
    "CVE-2013-6717"
  );
  script_bugtraq_id(54743, 55185, 57778, 60255, 62018, 64334, 64336);
  script_osvdb_id(101078, 101079, 84473, 84474, 84918, 89848, 93791, 96654);

  script_name(english:"IBM DB2 9.7 < Fix Pack 9 Multiple Vulnerabilities");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 9.7 running on
the remote host is prior to Fix Pack 9. It is, therefore, affected by
one or more of the following vulnerabilities :

  - The included software, GSKit, contains several errors
    related to SSL and TLS that can result in denial of
    service, information disclosures, or unauthorized
    insertion of an arbitrary root Certification Authority
    certificate. (CVE-2012-2190, CVE-2012-2191,
    CVE-2012-2203, CVE-2013-0169 / IC90395)

  - A stack-based buffer overflow exists related to
    'db2aud' and 'db2flacc' that allows a local attacker
    to elevate privileges to that of an instance owner. The
    'db2aud' issue does not affect installs on the Windows
    operating system. (CVE-2013-3475 / IC92495)

  - An unspecified error exists that allows an attacker to
    gain SELECT, INSERT, UPDATE, or DELETE permissions to
    database tables. Note that successful exploitation
    requires the rights EXPLAIN, SQLADM, or DBADM.
    (CVE-2013-4033 / IC94523)

  - An error exists related to the XSLT parser that allows
    a NULL pointer to be dereferenced. (CVE-2013-5466 /
    IC97470)

  - An error exists related to queries containing OLAP
    specifications that allows remote, authenticated
    attackers to close database connections and deactivate
    the database. (CVE-2013-6717 / IC95641)");
  # Security Fix List
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21450666#9");
  # Downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24036646");
  script_set_attribute(attribute:"solution", value:"
Apply IBM DB2 version 9.7 Fix Pack 9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ "^9\.7\.") exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.7.");

platform = get_kb_item_or_exit("DB2/"+port+"/Platform");
platform_name = get_kb_item("DB2/"+port+"/Platform_Name");
if (isnull(platform_name))
{
  platform_name = platform;
  report_phrase = "platform " + platform;
}
else
  report_phrase = platform_name;

report = "";

# Windows 32-bit/64-bit
if (platform == 5 || platform == 23)
{
  fixed_level = '9.7.900.250';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
# Others
else if (
  # Linux, 2.6 kernel 32/64-bit
  platform == 18 ||
  platform == 30 ||
  # AIX
  platform == 20
)
{
  fixed_level = '9.7.0.9';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
else
{
  info =
    'Nessus does not support version checks against ' + report_phrase + '.\n' +
    'To help us better identify vulnerable versions, please send the platform\n' +
    'number along with details about the platform, including the operating system\n' +
    'version, CPU architecture, and DB2 version to db2-platform-info@nessus.org.\n';
  exit(1, info);
}

if (report)
{
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "DB2", port, level);
