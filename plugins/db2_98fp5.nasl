#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59905);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_cve_id("CVE-2012-0712", "CVE-2012-0713", "CVE-2012-2180");
  script_bugtraq_id(52326, 53873);
  script_osvdb_id(
    79845,
    82753,
    82756,
    125198,
    125199
  );

  script_name(english:"IBM DB2 9.8 < Fix Pack 5 Multiple Vulnerabilities");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 9.8 running on
the remote host is prior to Fix Pack 5. It is, therefore, affected by
multiple vulnerabilities :

  - An authorized user with 'CONNECT' privileges from
    'PUBLIC' can cause a denial of service via unspecified
    methods related to DB2's XML feature. (CVE-2012-0712)

  - An unspecified information disclosure vulnerability
    exists related to the XML feature that can allow
    improper access to arbitrary XML files. (CVE-2012-0713)

  - An error exists related to the Distributed Relational
    Database Architecture (DRDA) that can allow denial of
    service conditions when processing certain request.
    (CVE-2012-2180)

  - A security bypass vulnerability exists due to the
    persistence of privileges when they're removed from
    users. An attacker can exploit this to execute non-DDL
    statements even if their privileges have been revoked.
    (VulnDB 125198)

  - An unspecified flaw exists that allows an attacker to
    cause a denial of service condition when Self Tuning
    Memory Manager (STMM) is enabled and DATABASE_MEMORY is
    set to AUTOMATIC. (VulnDB 125199)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC81836");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC81837");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC81839");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC82367");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21595316");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC83464");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC83403");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM DB2 version 9.8 Fix Pack 5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/10");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"plugin_type", value:"remote");
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
if (level !~ "^9\.8\.") exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.8.");

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

# Note: DB2 9.8x does not appear to be available for Windows
if (
  # Linux, 2.6 kernel 32/64-bit
  platform == 18 ||
  platform == 30 ||
  # AIX
  platform == 20
)
{
  fixed_level = '9.8.0.5';
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
