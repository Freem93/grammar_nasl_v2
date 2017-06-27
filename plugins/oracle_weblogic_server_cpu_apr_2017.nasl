#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99528);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/16 19:26:21 $");

  script_cve_id(
    "CVE-2016-1181",
    "CVE-2017-3506",
    "CVE-2017-3531",
    "CVE-2017-5638"
  );
  script_bugtraq_id(
    91068,
    91787,
    96729,
    97884
  );
  script_osvdb_id(
    139434,
    153025,
    155724,
    155750
  );
  script_xref(name:"CERT", value:"834067");
  script_xref(name:"IAVA", value:"2017-A-0113");
  script_xref(name:"EDB-ID", value:"41570");
  script_xref(name:"EDB-ID", value:"41614");
  script_xref(name:"TRA", value:"TRA-2017-16");
  script_xref(name:"ZDI", value:"ZDI-16-444");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (April 2017 CPU)");
  script_summary(english:"Checks for the patch.");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is
affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the
    Apache Struts component due to improper handling of
    multithreaded access to an ActionForm instance. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted multipart request, to execute
    arbitrary code or cause a denial of service condition.
    (CVE-2016-1181)

  - An unspecified flaw exists in the Web Services
    subcomponent that allows an unauthenticated, remote
    attacker to modify or delete arbitrary data accessible
    to the server. (CVE-2017-3506)

  - A remote code execution vulnerability exists in the Web
    Container subcomponent due to improper handling of
    reflected PartItem File requests. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary code.
    (CVE-2017-3531)

  - A remote code execution vulnerability exists in the
    Apache Struts component in the Jakarta Multipart parser
    due to improper handling of the Content-Type,
    Content-Disposition, and Content-Length headers.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted header value in the HTTP
    request, to execute arbitrary code. (CVE-2017-5638)");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?623d2c22");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3681811.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08e1362c");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2228898.1");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2017-16");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-444/");
  script_set_attribute(attribute:"see_also", value:"http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html");
  # https://threatpost.com/apache-struts-2-exploits-installing-cerber-ransomware/124844/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77e9c654");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2017 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts Jakarta Multipart Parser OGNL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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
  fix_ver = "10.3.6.0.170418";
  fix = "25388747";
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = "12.1.3.0.170418";
  fix = "25388793";
}
else if (version =~ "^12\.2\.1\.0($|[^0-9])")
{
  fix_ver = "12.2.1.0.170418";
  fix = "25388847";
}
else if (version =~ "^12\.2\.1\.1($|[^0-9])")
{
  fix_ver = "12.2.1.1.170418";
  fix = "25388843";
}
else if (version =~ "^12\.2\.1\.2($|[^0-9])")
{
  fix_ver = "12.2.1.2.170418";
  fix = "25388866";
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
