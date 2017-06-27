#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_40707. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(46347);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2015/01/15 16:37:16 $");

  script_cve_id("CVE-2010-1550", "CVE-2010-1551", "CVE-2010-1552", "CVE-2010-1553", "CVE-2010-1554", "CVE-2010-1555", "CVE-2010-1960", "CVE-2010-1961", "CVE-2010-1964", "CVE-2010-2709");
  script_osvdb_id(64973, 64974, 64975, 64976, 65427, 65428);
  script_xref(name:"HP", value:"emr_na-c02153379");
  script_xref(name:"HP", value:"emr_na-c02217439");
  script_xref(name:"HP", value:"emr_na-c02446520");
  script_xref(name:"HP", value:"SSRT010098");

  script_name(english:"HP-UX PHSS_40707 : s700_800 11.X OV NNM7.53 PA-RISC Intermediate Patch 26");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM7.53 PA-RISC Intermediate Patch 26 : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - Potential security vulnerabilities have been identified
    with HP OpenView Network Node Manager (OV NNM). These
    vulnerabilities could be exploited remotely to execute
    arbitrary code under the context of the user running the
    web server. References: CVE-2010-1964 (SSRT100026,
    ZDI-CAN-683) CVE-2010-1960 (SSRT100027, ZDI-CAN-684)
    CVE-2010-1961 (SSRT100028, ZDI-CAN-685).

  - Potential security vulnerabilities have been identified
    with HP OpenView Network Node Manager (OV NNM). These
    vulnerabilities could be exploited remotely to execute
    arbitrary code. References: CVE-2010-1550 (SSRT090225,
    ZDI-CAN-563) CVE-2010-1551 (SSRT090226, ZDI-CAN-564)
    CVE-2010-1552 (SSRT090227, ZDI-CAN-566) CVE-2010-1553
    (SSRT090228, ZDI-CAN-573) CVE-2010-1554 (SSRT090229,
    ZDI-CAN-574) CVE-2010-1555 (SSRT090230, ZDI-CAN-575).
    (HPSBMA02527 SSRT010098)

  - A potential security vulnerability has been identified
    with HP OpenView Network Node Manager (OV NNM). The
    vulnerability could be exploited remotely to execute
    arbitrary code under the context of the user running the
    web server."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02153379
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5f413ca"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02217439
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9c68a79"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02446520
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?094465cf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_40707 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP NNM CGI webappmon.exe OvJavaLocale Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/03");
  script_set_attribute(attribute:"patch_modification_date", value:"2010/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.11 11.23 11.31", proc:"parisc"))
{
  exit(0, "The host is not affected since PHSS_40707 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_40707", "PHSS_41242", "PHSS_41606", "PHSS_41857", "PHSS_42232", "PHSS_43046", "PHSS_43353");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-CORE", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-IPV6", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-JPN", version:"B.07.50.00")) flag++;
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
if (hpux_check_patch(app:"OVNNMgrRtDOC.OVNNM-ENG-DOC", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVDB-RUN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVEVENT-MIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVMIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVPMD-MIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVSNMP-MIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-EVNT", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-FW", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-SRV", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVEVENTMIN-MAN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVMIN-MAN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVSNMP-MIN-MAN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVWIN-MAN", version:"B.07.50.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
