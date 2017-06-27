#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79245);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/03 14:14:44 $");

  script_cve_id(
    "CVE-2014-3094",
    "CVE-2014-3095",
    "CVE-2014-6097",
    "CVE-2014-6159"
  );
  script_bugtraq_id(69546, 69550, 70983, 71006);
  script_osvdb_id(110594, 110608, 114334, 114335);

  script_name(english:"IBM DB2 9.7 < Fix Pack 10 Multiple Vulnerabilities");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 9.7 running on
the remote host is affected by the following vulnerabilities :

  - An input-validation error exists related to handling
    the 'ALTER MODULE' statement that allows buffer
    overflows. (CVE-2014-3094)

  - An error exists related to handling 'SELECT' statements
    with 'UNION' subqueries that allows application crashes.
    (CVE-2014-3095)

  - An error exists related to 'LUW' and 'ALTER TABLE'
    statement handling that allows application crashes.
    (CVE-2014-6097)

  - An error exists related to 'ALTER TABLE' statement
    handling that allows application crashes.
    (CVE-2014-6159)

Note that if a special vendor-supplied build has been installed, this
may be a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT02592");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21681631");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT02645");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21681623");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT03786");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21684812");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IT05105");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21688051");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 9.7 Fix Pack 10 or later.

Alternatively, contact the vendor regarding special builds containing
the fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("db2_das_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

app_name = "DB2";

level = get_kb_item_or_exit(app_name + "/" + port + "/Level");
if (level !~ "^9\.7\.")  audit(AUDIT_NOT_LISTEN, app_name + " 9.7.x", port);

platform = get_kb_item_or_exit(app_name+"/"+port+"/Platform");
platform_name = get_kb_item(app_name+"/"+port+"/Platform_Name");
if (isnull(platform_name))
{
  platform_name = platform;
  report_phrase = "platform " + platform;
}
else
  report_phrase = platform_name;

# Vendor notes special, contract-only builds are
# available as fixes for 9.7. The build numbers
# are not publicly available.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

report = "";

# Windows 32-bit/64-bit
if (platform == 5 || platform == 23)
{
  fixed_level = '9.7.1000.565';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + 
      '\n';
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
  fixed_level = '9.7.0.10';
  # Note things like last element can be like '9a'
  if (level =~ "^9\.7\.0\.[0-9]($|[^0-9])")
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + 
      '\n';
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
