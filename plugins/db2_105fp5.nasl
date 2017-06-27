#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82824);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/08/03 14:14:44 $");

  script_cve_id(
    "CVE-2014-6209",
    "CVE-2014-6210",
    "CVE-2014-8901"
  );
  script_bugtraq_id(71729, 71730, 71734);
  script_osvdb_id(115800, 115801, 115935);

  script_name(english:"IBM DB2 10.5 < Fix Pack 5 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the IBM DB2 10.5 server running on the
remote host is affected by the following vulnerabilities :

  - A remote, authenticated attacker, using a specially
    crafted 'ALTER TABLE' statement on an identity column,
    can cause a denial of service by crashing the server.
    (CVE-2014-6209)

  - A remote, authenticated attacker, by using multiple
    'ALTER TABLE' statements that specify the same column,
    can cause a denial of service by crashing the server.
    (CVE-2014-6210)

  - An error exists in the XML library that allows a remote,
    authenticated attacker to cause denial of service via a
    crafted XML query that results in excessive CPU usage.
    (CVE-2014-8901)");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21690787");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21690891");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21692358");
  script_set_attribute(attribute:"solution", value:"Apply DB2 version 10.5 Fix Pack 5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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
  fixed_level = '10.5.500.107';
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
  fixed_level = '10.5.0.5';
  if (level =~ "^10\.5\.0\.([0-4]|3a)$")
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
  if (report_verbosity > 0) security_warning(port:port, extra:report);
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, level);
