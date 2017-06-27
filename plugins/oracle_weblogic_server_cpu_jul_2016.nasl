#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92460);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/25 16:58:35 $");

  script_cve_id(
    "CVE-2016-3445",
    "CVE-2016-3499",
    "CVE-2016-3510",
    "CVE-2016-3586"
  );
  script_bugtraq_id(
    92003,
    92013,
    92016,
    92019
  );
  script_osvdb_id(
    141754,
    141755,
    141756,
    141757
  );
  script_xref(name:"TRA", value:"TRA-2016-21");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (July 2016 CPU)");
  script_summary(english:"Checks for the patch.");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is
affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Web Container
    subcomponent that allows an unauthenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-3445)

  - An unspecified flaw exists in the Web Container
    subcomponent that allows an unauthenticated, remote
    attacker to execute arbitrary code. (CVE-2016-3499)

  - A remote code execution vulnerability exists in the WLS
    Core component due to unsafe deserialize calls to the
    weblogic.corba.utils.MarshallObject object. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary code.
    (CVE-2016-3510)

  - An unspecified flaw exists in the WLS Core component
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2016-3586)");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453b5f8c");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/research/tra-2016-21");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2016 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
  fix_ver = "10.3.6.0.160719";
  fix = "23094342";
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = "12.1.3.0.160719";
  fix = "23094292";
}
else if (version =~ "^12\.2\.1\.")
{
  fix_ver = "12.2.1.0.160719";
  fix = "23094285";
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
