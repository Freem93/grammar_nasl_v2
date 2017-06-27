#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25905);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  script_cve_id("CVE-2007-2582", "CVE-2007-4270", "CVE-2007-4271", "CVE-2007-4272",
  "CVE-2007-4273", "CVE-2007-4275", "CVE-2007-4276", "CVE-2007-4417", "CVE-2007-4418", "CVE-2007-4423");
  script_bugtraq_id(23890, 25339, 26010);
  script_osvdb_id(
    40973,
    40975,
    40976,
    40977,
    40978,
    40979,
    40980,
    40981,
    40982,
    40983,
    40984,
    40989,
    40990,
    40991,
    40992,
    40993,
    40994
  );

  script_name(english:"IBM DB2 < 9 Fix Pack 3 / 8 Fix Pack 15 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the
remote host is affected by one or more of the following issues :

  - A local user may be able to overwrite arbitrary files,
    create arbitrary world-writeable directories, or gain
    root  privileges via symlink attacks or specially
    crafted  environment variables. (IY98210 / IY99261)

  - A user may be able to continue to execute a method even 
    once privileges for the method have been revoked.
    (IY88226,  version 8 only)

  - There is an unspecified issue allowing for privilege
    elevation when DB2 'execs' executables while running as 
    root. (IY98206 / IY98176)

  - There is an unspecified vulnerability related to
    incorrect authorization routines. (JR25940, version 8
    only)

  - There is an unspecified vulnerability in 
    'AUTH_LIST_GROUPS_FOR_AUTHID'. (IZ01828, version 9.1 
    only)

  - There is an unspecified vulnerability in the 'db2licm'
    and 'db2pd' tools. (IY97922 / IY97936)

  - There is an unspecified vulnerability involving
    'db2licd' and the 'OSSEMEMDBG' and 'TRC_LOG_FILE'
    environment variables. (IY98011 / IY98101)

  - There is a buffer overflow involving the 'DASPROF'
    environment variable. (IY97346 / IY99311)

  - There is an unspecified vulnerability that can arise 
    during instance and FMP startup. (IZ01923 / IZ02067)

  - The DB2JDS service may allow for arbitrary code
    execution without the need for authentication due to a
    stack overflow in an internal sprintf() call.
    (IY97750, version 8 only)

  - The DB2JDS service is affected by two denial of service
    issues that can be triggered by packets with an invalid
    LANG parameter or a long packet, which cause the process
    to terminate (version 8 only).

Note that there is currently insufficient information to determine to
what extent the first set of issues overlaps the others." );
  script_set_attribute(attribute:"see_also", value:"http://www.appsecinc.com/resources/alerts/db2/2007-01.shtml");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Aug/313");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Aug/314");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Aug/315");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Aug/316");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Aug/317");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Aug/318");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Aug/319");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Oct/153");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21255607");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21255352");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 9 Fix Pack 3 / 8.1 Fix Pack 15 / 8.2 Fix Pack 8
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(22, 119, 134);

  script_set_attribute(attribute:"plugin_publication_date", value: "2007/08/20");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
 
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 
  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:'db2das', default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/"+port+"/Level");
if (
  level !~ '^9\\.[01]\\.' &&
  level !~ '^([0-7]\\.|8\\.[01])'
)  exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.0, 9.1, or less than or equal to 8.1.x and thus is not affected.");

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

# Windows x86
if (platform == 5)
{
  if (level =~ '^9\\.')
  {
    fixed_level = '9.1.300.257';
    if (ver_compare(ver:level, fix:fixed_level) == -1)
      report = 
        '\n  Platform        : ' + platform_name +
        '\n  Installed level : ' + level +
        '\n  Fixed level     : ' + fixed_level + '\n';
  }
  else
  {
    fixed_level = '8.1.15.254';
    if (ver_compare(ver:level, fix:fixed_level) == -1)
      report =
        '\n  Platform        : ' + platform_name +
        '\n  Installed level : ' + level +
        '\n  Fixed level     : ' + fixed_level + '\n';
  }
}
else if (platform == 18)
{
  if (level =~ '^9\\.')
  {
    fixed_level = '9.1.0.3';
    if (ver_compare(ver:level, fix:fixed_level) == -1)
      report =
        '\n  Platform        : ' + platform_name +
        '\n  Installed level : ' + level +
        '\n  Fixed level     : ' + fixed_level + '\n';
  }
  else
  {
    if (level =~ '^8\\.1\\.0\\.') fixed_level = '8.1.0.136';
    else fixed_level = '8.1.2.136';

    if (ver_compare(ver:level, fix:fixed_level) == -1)
      report =
        '\n  Platform        : ' + platform_name +
        '\n  Installed level : ' + level +
        '\n  Fixed level     : ' + fixed_level + '\n';
  }
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
