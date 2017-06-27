#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(60098);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/02/04 22:38:29 $");

  script_cve_id(
    "CVE-2012-0711",
    "CVE-2012-2194",
    "CVE-2012-2196",
    "CVE-2012-2197"
  );
  script_bugtraq_id(52326, 54487);
  script_osvdb_id(79844, 84045, 84046, 84047);

  script_name(english:"IBM DB2 9.1 < Fix Pack 12 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote database server is affected by multiple issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"According to its version, the installation of IBM DB2 9.1 running on
the remote host is affected by one or more of the following issues :

  - An integer signedness error exists in the 'db2asrrm'
    process that can lead to a heap-based buffer overflow.
    Note that this issue does not affect Windows hosts.
    (#IC80561 / CVE-2012-0711)

  - An error exists related to the stored procedure
    'SQLJ.DB2_INSTALL_JAR' that can allow 'JAR' files to be
    overwritten. Note that this issue only affects Windows
    hosts. (#IC84019 / CVE-2012-2194)

  - An error exists related to the stored procedures
    'GET_WRAP_CFG_C' and 'GET_WRAP_CFG_C2' that can allow
    unauthorized access to XML files. (#IC84614 / 
    CVE-2012-2196)

  - An error exists related to the Java stored procedure
    infrastructure that can allow stack-based buffer
    overflows. (#IC84555 / CVE-2012-2197)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524334/30/0/threaded");
  # IC80561
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21588093");
  # IC84019
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC84019");
  # IC84614
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC84614");
  # IC84555
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC84555");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24033023");

  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 Version 9.1 Fix Pack 12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/23");

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


include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");


port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ '^9\\.1\\.')  exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.1.x and thus is not affected.");

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
  fixed_level = '9.1.1200.483';
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
  fixed_level = '9.1.0.12';
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
