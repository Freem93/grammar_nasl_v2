#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(51841);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/10/10 15:57:04 $");

  script_cve_id("CVE-2011-0731", "CVE-2011-1846", "CVE-2011-1847");
  script_bugtraq_id(46052, 47525);
  script_osvdb_id(70683, 72697, 72698);
  script_xref(name:"Secunia", value:"43059");
  script_xref(name:"Secunia", value:"44229");

  script_name(english:"IBM DB2 9.5 < Fix Pack 7 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the installation of IBM DB2 9.5 running on
the remote host is prior Fix Pack 7. It is, therefore, affected by the
following vulnerabilities :

  - The 'db2dasrrm' component included with such versions
    fails to perform sufficient bounds checks on user-
    supplied input, which an attacker could leverage to
    overflow the buffer, potentially resulting in arbitrary
    code execution on the remote system. (IC72028)

  - An unspecified error in the Relational Data Services
    component can be exploited to update statistics for
    tables without the appropriate privileges. (IC71413)

  - An error in the Relational Data Services component may
    grant users privileges to execute non-DDL statements
    after role membership has been revoked from its group.
    (IC71263)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-036/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Jan/583");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg1IC72028");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21293566#7");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg1IC71413");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg1IC71263");
  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 version 9.5 Fix Pack 7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/"+port+"/Level");
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
report = '';

# Windows 32-bit/64-bit
if (platform == 5 || platform == 23)
{
  fixed_level = '9.5.700.579';
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
  fixed_level = '9.5.0.7';
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
