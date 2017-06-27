#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50451);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/10/10 15:57:04 $");

  script_cve_id("CVE-2010-3474", "CVE-2010-3475", "CVE-2010-3731", "CVE-2011-0731");
  script_bugtraq_id(43291, 46052, 46077);
  script_osvdb_id(68121, 68122, 68315, 70683);
  script_xref(name:"Secunia", value:"41444");

  script_name(english:"IBM DB2 9.7 < Fix Pack 3 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 9.7 running on
the remote host is prior Fix Pack 3. It is, therefore, affected by one
or more of the following issues :

  - When privileges on a database object are revoked from
    PUBLIC, the dependent functions are not marked INVALID.
    As a result, users with execute privilege on the 
    function are still able to call it successfully.
    (IC68015)

  - If a compound SQL (compiled) statement has been issued
    by a user that is properly authorized, this is cached in
    the dynamic SQL cache.  Once cached, this same query can
    be executed by any user if that user has the proper
    authority. (IC70406)

  - Multiple vulnerabilities in 'db2dasrrm' component could 
    allow arbitrary code execution. (IC70539 / IC72029)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-035/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Jan/582");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-036/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Jan/583");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC68015");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC70406");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC70539");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC72029");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21450666");
  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 version 9.7 Fix Pack 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/14"); 
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/"+port+"/Level");
if (level !~ "^9\.7\.") exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.7 and thus is not affected.");

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
if (platform == 5 || platform  == 23)
{
  fixed_level = '9.7.300.3885';
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
  fixed_level = '9.7.0.3';
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
