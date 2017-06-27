#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84827);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/30 23:05:16 $");

  script_cve_id(
    "CVE-2014-8910",
    "CVE-2015-0157",
    "CVE-2015-0197",
    "CVE-2015-0198",
    "CVE-2015-0199",
    "CVE-2015-1883",
    "CVE-2015-1922",
    "CVE-2015-1935"
  );
  script_bugtraq_id(
    73278,
    73282,
    73283,
    75908,
    75911
  );
  script_osvdb_id(
    119566,
    119567,
    119568,
    124499,
    124500,
    124501,
    124502,
    124606
  );
  script_xref(name:"IAVB", value:"2015-B-0090");

  script_name(english:"IBM DB2 10.5 <= Fix Pack 5 Multiple Vulnerabilities");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the
remote host is version 10.5 prior or equal to Fix Pack 5. It is,
therefore, affected by one or more of the following vulnerabilities :

  - An unspecified error exists during the handling of
    SELECT statements with XML/XSLT functions that allows a
    remote attacker to gain access to arbitrary files.
    (CVE-2014-8910)

  - A flaw exists in the LUW component when handling SQL
    statements with unspecified Scaler functions. A remote,
    authenticated attacker can exploit this to cause a
    denial of service. (CVE-2015-0157)

  - An unspecified flaw in the General Parallel File System
    (GPFS) allows a local attacker to gain root privileges.
    CVE-2015-0197)

  - A flaw exists in the General Parallel File System
    (GPFS), related to certain cipherList configurations,
    that allows a remote attacker, using specially crafted
    data, to bypass authentication and execute arbitrary
    programs with root privileges. (CVE-2015-0198)

  - A denial of service vulnerability exists in the General
    Parallel File System (GPFS) that allows a local attacker
    to corrupt the kernel memory by sending crafted ioctl
    character device calls to the mmfslinux kernel module.
    (CVE-2015-0199)

  - An information disclosure vulnerability exists in the
    automated maintenance feature. An attacker with elevated
    privileges, by manipulating a stored procedure, can
    exploit this issue to disclose arbitrary files owned by
    the DB2 fenced ID on UNIX/Linux or the administrator on
    Windows. (CVE-2015-1883)

  - A flaw exists in the Data Movement feature when handling
    specially crafted queries. An authenticated, remote
    attacker can exploit this to delete database rows from a
    table without having the appropriate privileges.
    (CVE-2015-1922)

  - A flaw exists when handling SQL statements having
    unspecified LUW Scaler functions. An authenticated,
    remote attacker can exploit this to run arbitrary code,
    under the privileges of the DB2 instance owner, or to
    cause a denial of service. (CVE-2015-1935)");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21697987");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21697988");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21698308");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21902662");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21959650");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21902661");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor to obtain a special build with the interim fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ "^10\.5\.") audit(AUDIT_NOT_LISTEN, "DB2 10.5", port);

platform = get_kb_item_or_exit("DB2/"+port+"/Platform");
platform_name = get_kb_item("DB2/"+port+"/Platform_Name");
if (isnull(platform_name))
{
  platform_name = platform;
  report_phrase = "platform " + platform;
}
else
  report_phrase = platform_name;

report = NULL;

# Windows 32-bit/64-bit
if (platform == 5 || platform == 23)
{
  fixed_level = '10.5.500.107';
  if (ver_compare(ver:level, fix:fixed_level) <= 0)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : See solution\n';

  # If not paranoid and at 10.5.0.5 already,
  # do not report - we cannot tell if a special build is in place.
  if (level == fixed_level && report_paranoia < 2)
    exit(1, "Nessus is unable to determine if the patch has been applied or not.");
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
  fixed_level = '10.5.0.5';
  if (ver_compare(ver:level, fix:fixed_level) <= 0)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : See solution\n';

  # If not paranoid and at 10.5.0.5 already,
  # do not report - we cannot tell if a special build is in place.
  if (level == fixed_level && report_paranoia < 2)
    exit(1, "Nessus is unable to determine if the patch has been applied or not.");
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

if (!isnull(report))
{
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "DB2", port, level);
