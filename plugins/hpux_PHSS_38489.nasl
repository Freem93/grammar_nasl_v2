#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_38489. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(39380);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/18 20:51:41 $");

  script_cve_id("CVE-2008-1697", "CVE-2008-1842", "CVE-2008-3536", "CVE-2008-3537", "CVE-2008-3544", "CVE-2008-3545", "CVE-2009-3840", "CVE-2010-2710");
  script_osvdb_id(50076, 60200, 60424, 67328);
  script_xref(name:"HP", value:"emr_na-c01466051");
  script_xref(name:"HP", value:"emr_na-c01495949");
  script_xref(name:"HP", value:"emr_na-c01537275");
  script_xref(name:"HP", value:"emr_na-c01567813");
  script_xref(name:"HP", value:"emr_na-c01926980");
  script_xref(name:"HP", value:"SSRT080024");
  script_xref(name:"HP", value:"SSRT080033");
  script_xref(name:"HP", value:"SSRT080041");
  script_xref(name:"HP", value:"SSRT080042");
  script_xref(name:"HP", value:"SSRT080044");
  script_xref(name:"HP", value:"SSRT080045");
  script_xref(name:"HP", value:"SSRT080046");
  script_xref(name:"HP", value:"SSRT090177");

  script_name(english:"HP-UX PHSS_38489 : s700_800 11.X OV NNM7.53 IA-64 Intermediate Patch 20");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM7.53 IA-64 Intermediate Patch 20 : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - Potential vulnerabilities have been identified with HP
    OpenView Network Node Manager (OV NNM). The
    vulnerabilities could be exploited remotely to create a
    Denial of Service (DoS) or to execute arbitrary code.
    References: CVE-2008-3536, CVE-2008-3537, CVE-2008-3544
    (Bugtraq ID 28668). (HPSBMA02362 SSRT080044, SSRT080045,
    SSRT080042)

  - A potential vulnerability has been identified with HP
    OpenView Network Node Manager (OV NNM). The
    vulnerability could be exploited remotely execute
    arbitrary code or to create a Denial of Service (DoS).
    (HPSBMA02338 SSRT080024, SSRT080041)

  - A potential security vulnerability has been identified
    with HP OpenView Network Node Manager (OV NNM). The
    vulnerability could be exploited remotely to create a
    Denial of Service (DoS). (HPSBMA02374 SSRT080046)

  - Potential vulnerabilities have been identified with HP
    OpenView Network Node Manager (OV NNM). The
    vulnerabilities could be exploited remotely to execute
    arbitrary code with administrator priviliges or to
    create a Denial of Service (DoS). (HPSBMA02477
    SSRT090177)

  - A potential vulnerability has been identified with HP
    OpenView Network Node Manager (OV NNM). The
    vulnerability could be exploited remotely to execute
    arbitrary code or to create a Denial of Service (DoS).
    (HPSBMA02348 SSRT080033)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01466051
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?202438e1"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01495949
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c4897f2"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01537275
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd8ebfb4"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01567813
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39f46ac2"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01926980
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?499137a6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_38489 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP OpenView NNM 7.53, 7.51 OVAS.EXE Pre-Authentication Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
  script_set_attribute(attribute:"patch_modification_date", value:"2008/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/15");
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

if (!hpux_check_ctx(ctx:"11.23 11.31", proc:"ia64"))
{
  exit(0, "The host is not affected since PHSS_38489 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_38489", "PHSS_38783", "PHSS_39246", "PHSS_39640", "PHSS_39945", "PHSS_40375", "PHSS_40708", "PHSS_41243", "PHSS_41607", "PHSS_41858", "PHSS_42233", "PHSS_43047", "PHSS_43354");
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
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-PESA", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVMIB-CONTRIB", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNM-RUN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNMGR-JPN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNMGR-KOR", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNMGR-SCH", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-JPN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-KOR", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-SCH", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgrMan.OVNNM-RUN-MAN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgrRtDOC.OVNNM-DOC-REUS", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgrRtDOC.OVNNM-ENG-DOC", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVDB-RUN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVEVENT-MIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVMIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-EVNT", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-FW", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-SRV", version:"B.07.50.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
