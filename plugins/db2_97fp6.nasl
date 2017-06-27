#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59904);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/08/03 14:14:44 $");

  script_cve_id(
    "CVE-2011-4061",
    "CVE-2012-0709",
    "CVE-2012-0711",
    "CVE-2012-0712",
    "CVE-2012-0713",
    "CVE-2012-2180"
  );
  script_bugtraq_id(51181, 52326, 53873);
  script_osvdb_id(76456, 76457, 79844, 79845, 79846, 82753, 82756);

  script_name(english:"IBM DB2 9.7 < Fix Pack 6 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its version, the installation of DB2 9.7 running on the
remote host is prior to Fix Pack 6. It is, therefore, affected by
multiple vulnerabilities :

  - A local user can exploit a vulnerability in the bundled
    IBM Tivoli Monitoring Agent (ITMA) to escalate their
    privileges. (CVE-2011-4061)

  - An authorized user with 'CONNECT' and 'CREATEIN'
    privileges on a database can perform unauthorized
    reads on tables. (CVE-2012-0709)

  - An unspecified error in the DB2 Administration Server
    (DAS) can allow remote privilege escalation or denial
    of service via unspecified vectors. Note that this
    issue does not affect Windows hosts. (CVE-2012-0711)

  - An authorized user with 'CONNECT' privileges from
    'PUBLIC' can cause a denial of service via unspecified
    methods related to DB2's XML feature. (CVE-2012-0712)

  - An unspecified information disclosure error exists
    related to the XML feature that can allow improper
    access to arbitrary XML files. (CVE-2012-0713)

  - An error exists related to the Distributed Relational
    Database Architecture (DRDA) that can allow denial of
    service conditions when processing certain request.
    (CVE-2012-2180)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC79274");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC80729");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC81380");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC81390");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC81462");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC82234");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21450666");
  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 version 9.7 Fix Pack 6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/10");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/"+port+"/Level");
if (level !~ "^9\.7\.") exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.7.");

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
  fixed_level = '9.7.600.413';
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
  fixed_level = '9.7.0.6';
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
else audit(AUDIT_LISTEN_NOT_VULN, "DB2", port, level);
