#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77571);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 21:08:26 $");

  script_cve_id(
    "CVE-2013-6371",
    "CVE-2014-3094",
    "CVE-2014-3095",
    "CVE-2014-4805"
  );
  script_bugtraq_id(66715, 69541, 69546, 69550);
  script_osvdb_id(105617, 110593, 110594, 110608);

  script_name(english:"IBM DB2 10.5 < Fix Pack 4 Multiple Vulnerabilities");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 10.5 running on
the remote host is affected by the following vulnerabilities :

  - An error exists related to JavaScript Object Notation
    (JSON-C) handling, string parsing, and the hash function
    that allows denial of service attacks. (CVE-2013-6371)

  - A buffer overflow error exists related to handling
    'ALTER MODULE' statements that could lead to server
    crashes or arbitrary code execution. (CVE-2014-3094)

  - An error exists related to handling 'SELECT' statements
    having subqueries using 'UNION' that allows denial
    of service attacks. (CVE-2014-3095)

  - An error exists related to Columnar Data Engine (CDE)
    tables and 'LOAD' statement handling that allows local
    information disclosure. (CVE-2014-4805)");
  # Advisory
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21647054#4");
  # Download
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24038261");
  # CVE-2013-6371
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT02201");
  # CVE-2014-3094
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21681631");
  # CVE-2014-3095
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT02433");
  # CVE-2014-4805
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21681723");
  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 version 10.5 Fix Pack 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

app_name = "DB2";

level = get_kb_item_or_exit(app_name + "/" + port + "/Level");
if (level !~ "^10\.5\.")  audit(AUDIT_NOT_LISTEN, app_name + " 10.5.x", port);

platform = get_kb_item_or_exit(app_name+"/"+port+"/Platform");
platform_name = get_kb_item(app_name+"/"+port+"/Platform_Name");
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
  fixed_level = '10.5.400.191';
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
  fixed_level = '10.5.0.4';
  if (level =~ "^10\.5\.0\.([0-3]|3a)$")
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
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, level);
