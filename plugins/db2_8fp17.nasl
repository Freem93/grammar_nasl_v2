#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34195);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  script_cve_id(
    "CVE-2008-2154",
    "CVE-2008-3856",
    "CVE-2008-3958",
    "CVE-2008-3960",
    "CVE-2008-6820",
    "CVE-2008-6821"
  );
  script_bugtraq_id(31058, 35408, 35409);
  script_osvdb_id(46262, 48144, 48146, 48147, 48148, 48149, 49949);
  script_xref(name:"Secunia", value:"31787");

  script_name(english:"IBM DB2 8 < Fix Pack 17 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues." );
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 8 running on the
remote host is affected by multiple issues :

  - By sending malicious DB2 UDB v7 client CONNECT/DETACH
    requests it may be possible to crash the remote DB2 
    server. (IZ08134)

  - Failure to switch the owner of the 'DB2FMP' process
    may lead to a security vulnerability on Unix / Linux
    platforms. (IZ20350)

  - DAS server code is affected by a buffer overflow 
    vulnerability. (IZ22004)

  - Using INSTALL_JAR, it may be possible to create and 
    overwrite critical files on the system. (IZ22142)

  - DB2 does not mark inoperative or drop views and triggers
    if the definer cannot maintain the objects. (IZ22287)

  - By sending malicious packets to 'DB2JDS', it may be 
    possible to crash the remote DB2 server. (JR29274)

  - While running on Windows 'DB2FMP' runs with OS
    privileges. (JR30228)" );
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21255352" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ08134" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ20350" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ22004" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ22142" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ22287" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR29274" );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR30228" );
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 UDB version 8 Fix Pack 17 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 20, 119, 264);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/12");
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
if (level !~ '^8\\.1\\.') exit(0, "The version of IBM DB2 listening on port "+port+" is not 8.1 and thus is not affected.");

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
  fixed_level = '8.1.17.644';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report = 
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
# Linux, 2.6 Kernel 32-bit
else if (platform == 18)
{
  if (level =~ '^8\\.1\\.0\\.') fixed_level = '8.1.0.152';
  else fixed_level = '8.1.2.152';

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
