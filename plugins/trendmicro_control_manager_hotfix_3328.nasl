#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93482);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:42:25 $");

  script_cve_id("CVE-2016-6220");
  script_osvdb_id(
    142765,
    142766,
    142767,
    142768,
    142769,
    142770,
    142771
    );
  script_xref(name:"ZDI", value:"ZDI-16-455");
  script_xref(name:"ZDI", value:"ZDI-16-456");
  script_xref(name:"ZDI", value:"ZDI-16-457");
  script_xref(name:"ZDI", value:"ZDI-16-458");
  script_xref(name:"ZDI", value:"ZDI-16-459");
  script_xref(name:"ZDI", value:"ZDI-16-460");
  script_xref(name:"ZDI", value:"ZDI-16-461");
  script_xref(name:"ZDI", value:"ZDI-16-462");

  script_name(english:"Trend Micro Control Manager 6.x < 6.0 SP3 Hotfix 3328 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of cgiHandlerScheduleDownload.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A security management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Trend Micro Control Manager application
installed on the remote Windows host is 6.x prior to 6.0 SP 3 Hotfix
3328 (6.0.0.3328). It is, therefore, affected by the following
vulnerabilities :

  - A directory traversal vulnerability exists in the
    task_controller.php script due to improper sanitization
    of user-supplied input to the 'url' parameter. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted request, to disclose arbitrary
    files. (VulnDB 142765)

  - A flaw exists in the AdHocQuery_SelectView.aspx script
    due to improper sanitization of user-supplied input
    before executing XML queries. An authenticated, remote
    attacker can exploit this to inject XPATH content,
    resulting in gaining access to sensitive information.
    (VulnDB 142766)

  - Multiple XML external entity (XXE) injection
    vulnerabilities exist due to an incorrectly configured
    XML parser accepting XML external entities from
    untrusted sources. Specifically, these issues occur in
    the DeploymentPlan_Event_Handler.aspx, ProductTree.aspx,
    and TreeUserControl_process_tree_event.aspx scripts. An
    authenticated, remote attacker can exploit these issues,
    via specially crafted XML data, to gain access to
    sensitive information. (VulnDB 142767, 142768, 142769)

  - Multiple SQL injection (SQLi) vulnerabilities exist due
    to improper sanitization of user-supplied input before
    using it in SQL queries. Specifically, these issues
    occur in the AdHocQuery_CustomProfiles.aspx and
    cgiCMUIDispatcher.exe scripts. An authenticated, remote
    attacker can exploit these issues to inject SQL queries
    against the back-end database, resulting in the
    disclosure or manipulation of arbitrary data. Moreover,
    the attacker can exploit these issues to inject PHP
    payloads, which can be then called and executed.
    (VulnDB 142770, 142771)");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/solution/1114749");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-16-455/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-16-456/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-16-457/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-16-458/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-16-459/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-16-460/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-16-461/");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-16-462/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trend Micro Control Manager version 6.0 SP3 Hotfix
3328 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:control_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_control_manager_detect.nbin");
  script_require_keys("installed_sw/Trend Micro Control Manager");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

appname = "Trend Micro Control Manager";
install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

base_ver = install['version'];
path = install['path'];

if (base_ver =~ "^6\.")
{
  dll = path + "\cgiHandlerScheduleDownload.dll";
  version = hotfix_get_fversion(path:dll);
  hotfix_handle_error(error_code:version['error'], file:dll, appname:appname, exit_on_fail:TRUE);
  hotfix_check_fversion_end();

  version = join(sep:'.', version['value']);
  fix = "6.0.0.3328";

  if ( ver_compare(ver:version, fix:fix, strict:FALSE) <0 )
  {
    port = kb_smb_transport();

    report =  '\nProduct       :  ' + appname +
              '\nFile          :  ' + dll +
              '\nFile Version  :  ' + version +
              '\nFixed Version :  ' + fix +
              '\n';
    security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  }
  else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, dll);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, base_ver);