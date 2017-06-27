#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_40374. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43142);
  script_version("$Revision: 1.37 $");
  script_cvs_date("$Date: 2016/11/18 20:51:41 $");

  script_cve_id("CVE-2008-2086", "CVE-2008-5339", "CVE-2008-5340", "CVE-2008-5341", "CVE-2008-5342", "CVE-2008-5343", "CVE-2008-5344", "CVE-2008-5345", "CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5356", "CVE-2008-5357", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360", "CVE-2009-0898", "CVE-2009-3845", "CVE-2009-3846", "CVE-2009-3847", "CVE-2009-3848", "CVE-2009-3849", "CVE-2009-4176", "CVE-2009-4177", "CVE-2009-4178", "CVE-2009-4179", "CVE-2009-4180", "CVE-2009-4181");
  script_osvdb_id(50495, 50496, 50497, 50499, 50500, 50502, 50503, 50505, 50506, 50508, 50509, 50510, 50511, 50512, 50513, 50514, 50515, 50516, 50517, 60923, 60924, 60925, 60926, 60927, 60928, 60929, 60930, 60931, 60932, 60933, 60934);
  script_xref(name:"HP", value:"emr_na-c01950877");
  script_xref(name:"HP", value:"emr_na-c02000725");
  script_xref(name:"HP", value:"SSRT090049");
  script_xref(name:"HP", value:"SSRT090257");

  script_name(english:"HP-UX PHSS_40374 : s700_800 11.X OV NNM7.53 PA-RISC Intermediate Patch 25");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM7.53 PA-RISC Intermediate Patch 25 : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - Potential security vulnerabilities have been identified
    with HP OpenView Network Node Manager (OV NNM). These
    vulnerabilities could be exploited remotely to execute
    arbitrary code. References: CVE-2009-0898 (SSRT090101)
    CVE-2009-3845 (SSRT090037, ZDI-CAN-453) CVE-2009-3846
    (SSRT090122, ZDI-CAN-526) CVE-2009-3847 (SSRT090128,
    ZDI-CAN-532) CVE-2009-3848 (SSRT090129, ZDI-CAN-522)
    CVE-2009-3849 (SSRT090130, ZDI-CAN-523) CVE-2009-4176
    (SSRT090131, ZDI-CAN-532) CVE-2009-4177 (SSRT090132,
    ZDI-CAN-538) CVE-2009-4178 (SSRT090133, ZDI-CAN-539)
    CVE-2009-4179 (SSRT090134, ZDI-CAN-540) CVE-2009-4180
    (SSRT090135, ZDI-CAN-542) CVE-2009-4181 (SSRT090164,
    ZDI-CAN-549). (HPSBMA02483 SSRT090257)

  - Potential security vulnerabilities have been identified
    with the Java Runtime Environment (JRE) and Java
    Developer Kit (JDK) delivered with HP OpenView Network
    Node Manager (OV NNM). These vulnerabilities may allow
    remote unauthorized access, privilege escalation,
    execution of arbitrary code, and creation of a Denial of
    Service (DoS) . (HPSBMA02486 SSRT090049)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01950877
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?422f4693"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02000725
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72ecd727"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_40374 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP OpenView Network Node Manager ovalarm.exe CGI Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_cwe_id(94, 119, 189, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/26");
  script_set_attribute(attribute:"patch_modification_date", value:"2010/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_40374 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_40374", "PHSS_40707", "PHSS_41242", "PHSS_41606", "PHSS_41857", "PHSS_42232", "PHSS_43046", "PHSS_43353");
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
