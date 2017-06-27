#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33128);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  script_cve_id("CVE-2008-2154", "CVE-2008-3852", "CVE-2008-3854", "CVE-2008-3855", "CVE-2008-3856", "CVE-2008-3857", "CVE-2008-6821");
  script_bugtraq_id(29601, 35408, 35409);
  script_osvdb_id(
    46262,
    46263,
    46264,
    46265,
    46266,
    46267,
    46270,
    46271,
    48146,
    48147,
    48429
  );
  script_xref(name:"Secunia", value:"30558");

  script_name(english:"IBM DB2 < 9 Fix Pack 5 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the IBM DB2 server running on the remote
host is affected by one or more of the following issues :

  - There is an unspecified security vulnerability
    related to a 'DB2FMP' process. (IZ20352)

  - On Windows, the 'DB2FMP' process is running with OS
    privileges. (JR30026)

  - The CLR stored procedure deployment feature of IBM 
    Database Add-Ins for Visual Studio can be used to
    escalate privileges or launch a denial of service
    attack against a DB2 server. (JR28432)

  - The password used to connect to the database can be
    seen in plaintext in a memory dump. (JR27422)

  - There is a possible stack variable overrun in
    'SQLRLAKA()'. (IZ16346)

  - A local privilege escalation vulnerability via file
    creation can result in root-level access. (IZ12735)

  - There are possible buffer overflows involving 'XQUERY', 
    'XMLQUERY', 'XMLEXISTS', and 'XMLTABLE'. (IZ18434)

  - A specially crafted client CONNECT request could
    crash the server. (IZ07299)

  - There is an unspecified remote buffer overflow in
    DAS server code. (IZ22188)

  - INSTALL_JAR can be used to create or overwrite
    critical system files. (IZ21983)");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/496406/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/496405/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21255607");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ20352");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1JR30026");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1JR28432");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ12735");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1JR27422");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ16346");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ18434");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ07299");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ22188");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IZ21983");
  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 Version 9 Fix Pack 5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 119, 200, 264);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/10");
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

level = get_kb_item("DB2/" + port + "/Level");
if (level !~ '^9\\.[01]\\.') exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.0 or 9.1 and thus is not affected.");

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
  fixed_level = '9.1.500.555';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
# Linux, 2.6 Kernel 32-bit
else if (platform == 18)
{
  fixed_level = '9.1.0.5';
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
else exit(0, "IBM DB2 "+level+" on " + report_phrase + " is listening on port "+port+" and is not affected.");
