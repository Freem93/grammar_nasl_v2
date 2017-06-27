#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59644);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2010-4476", "CVE-2012-0710");
  script_bugtraq_id(46091, 52326);
  script_osvdb_id(70965, 79842, 80347);

  script_name(english:"IBM DB2 9.1 < Fix Pack 11 Multiple DoS");
  script_summary(english:"Checks DB2 signature");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of
service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 9.1 running on
the remote host is prior to Fix Pack 11. It is, therefore, affected by
multiple  denial of service vulnerabilities :

  - The version of Java that is bundled with the
    application can enter an infinite loop when handling
    certain operations related to floating point numbers.
    (CVE-2010-4476)

  - The Distributed Relational Database Architecture (DRDA)
    contains an error that can allow denial of service
    conditions when handling certain maliciously crafted
    requests. (CVE-2012-0710)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www-304.ibm.com/support/docview.wss?uid=swg21468291");
  script_set_attribute(attribute:"see_also", value:"http://www-304.ibm.com/support/docview.wss?uid=swg1IC76781");
  script_set_attribute(attribute:"see_also", value:"http://www-304.ibm.com/support/docview.wss?uid=swg21588090");
  script_set_attribute(attribute:"see_also", value:"http://www-304.ibm.com/support/docview.wss?uid=swg21255607");
  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 Version 9.1 Fix Pack 11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/21");

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

level = get_kb_item_or_exit("DB2/"+port+"/Level");
if (level !~ "^9\.[01]\.") exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.0 or 9.1.");

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
  fixed_level = '9.1.1100.795';
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
  fixed_level = '9.1.0.11';
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
else audit(AUDIT_LISTEN_NOT_VULN, "DB2", port, level);
