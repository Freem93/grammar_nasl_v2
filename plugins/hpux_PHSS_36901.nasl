#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_36901. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(26897);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/11/18 20:51:41 $");

  script_cve_id("CVE-2007-3872", "CVE-2007-6204", "CVE-2007-6343");
  script_osvdb_id(38935, 39527, 39529, 39530, 39531, 39532);
  script_xref(name:"TRA", value:"TRA-2007-09");
  script_xref(name:"HP", value:"emr_na-c01112038");
  script_xref(name:"IAVT", value:"2007-T-0033");
  script_xref(name:"HP", value:"emr_na-c01188923");
  script_xref(name:"HP", value:"emr_na-c01218087");
  script_xref(name:"HP", value:"SSRT061260");
  script_xref(name:"HP", value:"SSRT061261");
  script_xref(name:"HP", value:"SSRT071319");

  script_name(english:"HP-UX PHSS_36901 : s700_800 11.X OV NNM7.51 PA-RISC Intermediate Patch 17");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM7.51 PA-RISC Intermediate Patch 17 : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential vulnerability has been identified with HP
    OpenView Network Node Manager (OV NNM). This
    vulnerability could be exploited remotely by an
    unauthorized user to execute arbitrary code with the
    permissions of the NNM server. (HPSBMA02281 SSRT061261)

  - A potential vulnerability has been identified with HP
    OpenView Network Node Manager (OV NNM) running Shared
    Trace Service. The vulnerability could be remotely
    exploited to execute arbitrary code. (HPSBMA02242
    SSRT061260)

  - A potential vulnerability has been identified with HP
    OpenView Network Node Manager (OV NNM). This
    vulnerability could by exploited remotely to allow cross
    site scripting (XSS). (HPSBMA02283 SSRT071319)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2007-09");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01112038
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?149b8149"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01188923
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3312cdf1"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01218087
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d908af80"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_36901 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP OpenView Network Node Manager OpenView5.exe CGI Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(79, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/26");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/30");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"HP-UX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/HP-UX/version", "Host/HP-UX/swlist");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("hpux.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/HP-UX/version")) audit(AUDIT_OS_NOT, "HP-UX");
if (!get_kb_item("Host/HP-UX/swlist")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (!hpux_check_ctx(ctx:"11.00 11.11 11.23 11.31", proc:"parisc"))
{
  exit(0, "The host is not affected since PHSS_36901 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_36901", "PHSS_37273");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-CORE", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-PD", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-PESA", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVMIB-CONTRIB", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNM-RUN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNMGR-JPN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNMGR-KOR", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNMGR-SCH", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVRPT-RUN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-JPN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-KOR", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-SCH", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgrMan.OVNNM-RUN-MAN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgrRtDOC.OVNNM-DOC-REUS", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgrRtDOC.OVNNM-ENG-DOC", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVDB-RUN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVEVENT-MIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVMIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVSNMP-MIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-EVNT", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-FW", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-SRV", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVEVENTMIN-MAN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVSNMP-MIN-MAN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVWIN-MAN", version:"B.07.50.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
