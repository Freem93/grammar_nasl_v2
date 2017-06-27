#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42044);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2009-3471", "CVE-2009-3472", "CVE-2009-3473"); 
  script_bugtraq_id(36540);
  script_osvdb_id(58477, 58478, 58479, 60512);
  script_xref(name:"Secunia", value:"36890");

  script_name(english:"IBM DB2 9.1 < Fix Pack 8 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the IBM DB2 server running on the remote
host is prior to 9.1 Fix Pack 8. It is, therefore, affected by
multiple vulnerabilities :

  - MODIFIED SQL DATA table function is not dropped even if 
    the maintainer does not have privileges to maintain the 
    objects. (IZ46773)

  - It may be possible for an unauthorized user to insert,
    update, or delete rows in a table. (IZ50078)
 
  - An user without 'SETSESSIONUSER' privilege can perform
    'SET SESSION AUTHORIZATION'. (IZ55883)

  - The 'DASAUTO' command can be run by a non-privileged
    user. (IZ40340)");

  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21403619");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21386689");
  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 Version 9.1 Fix Pack 8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
 
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 
  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:'db2das', default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/"+port+"/Level");
if (level !~ '^9\\.[01]\\.') exit(0, "The version of DB2 listening on port "+port+" is not 9.0 or 9.1.");

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
  fixed_level = '9.1.800.1023';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
else if (platform == 18 || platform == 30)
{
  fixed_level = '9.1.0.8';
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
else exit(0, "The installed IBM DB2 platform / level are "+platform_name+" / "+level+" and thus not affected.");
