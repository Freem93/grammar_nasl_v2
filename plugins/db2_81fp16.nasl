#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30153);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  script_cve_id("CVE-2007-3676", "CVE-2007-5757", "CVE-2008-0698");
  script_bugtraq_id(27596, 27680, 27681);
  script_osvdb_id(41629, 41630, 41632);

  script_name(english:"IBM DB2 < 8.1 Fix Pack 16 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues." );
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the
remote host is affected by one or more of the following issues :

  - A local user may be able to gain root privileges using
    the 'db2pd' tool. (IZ03546)

  - The 'b2dart' tool executes a TPUT command, which
    effectively allows users to run commands as the DB2
    instance owner. (IZ03647)

  - A buffer overflow and invalid memory access 
    vulnerability exist in the DAS server code. (IZ05496)

  - An unspecified vulnerability in 'SYSPROC.ADMIN_SP_C'.
    (IZ06972)

  - An unspecified vulnerability exists due to incorrect
    authorization checking in 'ALTER TABLE' statements.
    (IZ07337)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6734f378" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ba276a6" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/72" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/73" );
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21256235" );
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 UDB Version 8.1 Fix Pack 16 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 264, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/05");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
 
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 
  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:'db2das', default:523, exit_on_fail:TRUE);

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
  fixed_level = '8.1.16.429';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report = 
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
# Linux, 2.6 Kernel 32-bit
else if (platform == 18)
{
  if (level =~ '^8\\.1\\.0\\.') fixed_level = '8.1.0.144';
  else fixed_level = '8.1.2.144';

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
  if (report_verbosity > 0)  security_hole(port:port, extra:report);
  else security_hole(port);
}
else exit(0, "IBM DB2 "+level+" on " + report_phrase + " is listening on port "+port+" and is not affected.");
