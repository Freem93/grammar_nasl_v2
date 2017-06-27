#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_38148. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(39378);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/05/11 13:32:17 $");

  script_cve_id("CVE-2007-3698", "CVE-2007-3922", "CVE-2007-4349", "CVE-2007-5000", "CVE-2007-6388");
  script_bugtraq_id(26838, 27237);
  script_osvdb_id(36662, 36663);
  script_xref(name:"HP", value:"emr_na-c01601492");
  script_xref(name:"HP", value:"emr_na-c01607558");
  script_xref(name:"HP", value:"emr_na-c01607570");
  script_xref(name:"HP", value:"SSRT071465");
  script_xref(name:"HP", value:"SSRT071481");
  script_xref(name:"HP", value:"SSRT080059");

  script_name(english:"HP-UX PHSS_38148 : s700_800 11.X OV NNM7.53 IA-64 Intermediate Patch 19");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM7.53 IA-64 Intermediate Patch 19 : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - Potential security vulnerabilities have been identified
    with HP OpenView Network Node Manager (OV NNM). The
    vulnerabilities could be exploited remotely to gain
    unauthorized access or to create a Denial of Service
    (DoS). References: CVE-2007-3698, CVE-2007-3922, SUN
    Alert 102995, 102997. (HPSBMA02384 SSRT071465)

  - A potential security vulnerability has been identified
    with HP OpenView Network Node Manager (OV NNM). The
    vulnerability could be exploited remotely to create a
    Denial of Service (DoS). (HPSBMA02392 SSRT071481)

  - Potential security vulnerabilities have been identified
    with HP OpenView Network Node Manager (OV NNM). The
    vulnerabilities could be exploited remotely to allow
    cross site scripting (XSS). (HPSBMA02388 SSRT080059)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01601492
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4abf7ab6"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01607570
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04c58123"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01607558
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb0e7f7d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_38148 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/11");
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
  exit(0, "The host is not affected since PHSS_38148 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_38148", "PHSS_38489", "PHSS_38783", "PHSS_39246", "PHSS_39640", "PHSS_39945", "PHSS_40375", "PHSS_40708", "PHSS_41243", "PHSS_41607", "PHSS_41858", "PHSS_42233", "PHSS_43047", "PHSS_43354");
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
