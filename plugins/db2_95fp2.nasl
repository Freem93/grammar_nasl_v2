#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34056);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  script_cve_id("CVE-2008-2154", "CVE-2008-3852", "CVE-2008-4693", "CVE-2008-4692", "CVE-2008-6821");
  script_bugtraq_id(30859, 35408, 35409);
  script_osvdb_id(46270, 48146, 48147, 49949, 49950);
  script_xref(name:"Secunia", value:"31635");

  script_name(english:"IBM DB2 9.5 < Fix Pack 2 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installation of IBM DB2 9.5 running on the remote host does not
have Fix Pack 2 applied. It is, therefore, affected by the following
issues :

  - DB2 does not mark inoperative or drop views and triggers
    if the definer cannot maintain the objects (IZ22307).

  - Password-related connection string keyword values may
    appear in trace output (IZ28489).

  - There is an unspecified vulnerability in the way CLR 
    Stored Procedures for Visual Studio from IBM database 
    add-ins are deployed (JR28431). 

  - There is an unspecified buffer overflow in DAS server
    code (IZ22190).

  - INSTALL_JAR can be used to create or overwrite critical
    files on a system (IZ22143).

  - On Windows, the db2fmp process is running with OS
    privileges (JR30227).");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21293566");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ22307");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ28489");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR28431");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ22190");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ22143");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR30227");
  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 version 9.5 Fix Pack 2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 119, 200, 264);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/28");
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
if (level !~ '^9\\.5\\.') exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.5 and thus is not affected.");

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
  fixed_level = '9.5.200.315';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report = 
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
# Linux, 2.6 Kernel 32-bit
else if (platform == 18)
{
  fixed_level = '9.5.0.2';
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
exit(0, "IBM DB2 "+level+" on " + report_phrase + " is listening on port "+port+" and is not affected.");
