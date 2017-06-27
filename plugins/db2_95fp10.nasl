#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62629);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/09/06 13:33:33 $");

  script_cve_id(
    "CVE-2012-0713",
    "CVE-2012-2194",
    "CVE-2012-2196",
    "CVE-2012-2197"
  );
  script_bugtraq_id(53873, 54487);
  script_osvdb_id(82753, 84045, 84046, 84047);

  script_name(english:"IBM DB2 9.5 < Fix Pack 10 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote database server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"According to its version, the installation of IBM DB2 9.5 running on
the remote host is affected by one or more of the following issues :

  - An unspecified information disclosure error exists
    related to the XML feature that can allow improper
    access to arbitrary XML files. (#IC81461, CVE-2012-0713)

  - An error exists related to the stored procedure
    'SQLJ.DB2_INSTALL_JAR' that can allow 'JAR' files to be
    overwritten. Note that this issue only affects Windows
    hosts. (#IC84711, CVE-2012-2194)

  - An error exists related to the stored procedures
    'GET_WRAP_CFG_C' and 'GET_WRAP_CFG_C2' that can allow
    unauthorized access to XML files. (#IC84712,
    CVE-2012-2196)

  - An error exists related to the Java stored procedure
    infrastructure that can allow stack-based buffer
    overflows. (#IC84752, CVE-2012-2197)"
  );
  # Downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24033308");
  # IC81461
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC81461");
  # IC84711
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC84711");
  # IC84712
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC84712");
  # IC84752
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC84752");
  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 version 9.5 Fix Pack 10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
 
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
 
  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ '^9\\.5\\.')  exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.5.");

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
  fixed_level = '9.5.1000.163';
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
  fixed_level = '9.5.0.10';
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
