#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94290);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/23 17:47:51 $");

  script_cve_id(
    "CVE-2015-7501",
    "CVE-2016-3505",
    "CVE-2016-5488",
    "CVE-2016-5531",
    "CVE-2016-5535",
    "CVE-2016-5601"
  );
  script_bugtraq_id(
    78215,
    93627,
    93692,
    93704,
    93708,
    93730
  );
  script_osvdb_id(
    129952,
    130424,
    130493,
    145859,
    145860,
    145861,
    145862,
    145863  
  );
  script_xref(name:"CERT", value:"576313");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (October 2016 CPU)");
  script_summary(english:"Checks for the patch.");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is
affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the
    JMXInvokerServlet interface due to unsafe deserialize
    calls of unauthenticated Java objects to the Apache
    Commons Collections (ACC) library. An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code. (CVE-2015-7501)

  - An unspecified flaw exists in the Java Server Faces
    subcomponent that allows an authenticated, remote
    attacker to execute arbitrary code. (CVE-2016-3505)

  - An unspecified flaw exists in the Web Container
    subcomponent that allows an unauthenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-5488)

  - An unspecified flaw exists in the WLS-WebServices
    subcomponent that allows an unauthenticated, remote
    attacker to execute arbitrary code. (CVE-2016-5531)

  - An unspecified flaw that allows an unauthenticated,
    remote attacker to execute arbitrary code. No other
    details are available. (CVE-2016-5535)

  - An unspecified flaw exists in the CIE Related
    subcomponent that allows a local attacker to impact
    confidentiality and integrity. (CVE-2016-5601)");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bac902d5");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("oracle_weblogic_server_installed.nbin");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Oracle WebLogic Server";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ohome = install["Oracle Home"];
subdir = install["path"];
version = install["version"];

fix = NULL;
fix_ver = NULL;

# individual security patches
if (version =~ "^10\.3\.6\.")
{
  fix_ver = "10.3.6.0.161018";
  fix = "23743997";
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = "12.1.3.0.161018";
  fix = "23744018";
}
else if (version =~ "^12\.2\.1\.0($|[^0-9])")
{
  fix_ver = "12.2.1.0.161018";
  fix = "24286148";
}
else if (version =~ "^12\.2\.1\.1($|[^0-9])")
{
  fix_ver = "12.2.1.1.161018";
  fix = "24286152";
}


if (!isnull(fix_ver) && ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1)
{
  port = 0;
  report =
    '\n  Oracle home    : ' + ohome +
    '\n  Install path   : ' + subdir +
    '\n  Version        : ' + version +
    '\n  Required patch : ' + fix +
    '\n';
  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);
