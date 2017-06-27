#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23936);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/08/03 14:14:44 $");

  script_cve_id("CVE-2006-4257");
  script_bugtraq_id(19586);
  script_osvdb_id(27993);

  script_name(english:"IBM DB2 < 8.1 Fix Pack 13 CONNECT Processing Unspecified DoS");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of service
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the
remote host may crash in certain scenarios, such as when a user
connects using a specially crafted ACCSEC command during the handshake
process.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/445298/100/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/454307/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg24013114" );
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 UDB version 8.1 FixPak 13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/23");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/08/18");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
 
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
 
  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
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

# Windows 32-bit
if (platform == 5)
{
  fixed_level = '8.1.13.193';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  fixed level     : ' + fixed_level + '\n';
}
# Linux, 2.6 Kernel 32-bit
else if (platform == 18)
{
  if (level =~ '^8\\.1\\.0\\.') fixed_level = '8.1.0.120';
  else fixed_level = '8.1.2.120';

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
  if (report_verbosity > 0) security_warning(port:port, extra:report);
  else security_warning(port);
}
else exit(0, "IBM DB2 "+level+" on " + report_phrase + " is listening on port "+port+" and is not affected.");
