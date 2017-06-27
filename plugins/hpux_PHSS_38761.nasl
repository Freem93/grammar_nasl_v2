#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_38761. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(34952);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/18 20:51:41 $");

  script_cve_id("CVE-2007-3698", "CVE-2007-3922", "CVE-2007-4349", "CVE-2007-5000", "CVE-2007-6388", "CVE-2008-1842", "CVE-2008-3545", "CVE-2008-4559", "CVE-2008-4560", "CVE-2008-4561", "CVE-2008-4562", "CVE-2009-0205");
  script_bugtraq_id(26838, 27237);
  script_osvdb_id(36662, 36663, 53235, 53236, 53237, 53238, 53239, 53240, 53241);
  script_xref(name:"HP", value:"emr_na-c01466051");
  script_xref(name:"HP", value:"emr_na-c01567813");
  script_xref(name:"HP", value:"emr_na-c01601492");
  script_xref(name:"HP", value:"emr_na-c01607558");
  script_xref(name:"HP", value:"emr_na-c01607570");
  script_xref(name:"HP", value:"emr_na-c01661610");
  script_xref(name:"HP", value:"SSRT071465");
  script_xref(name:"HP", value:"SSRT071481");
  script_xref(name:"HP", value:"SSRT080024");
  script_xref(name:"HP", value:"SSRT080041");
  script_xref(name:"HP", value:"SSRT080046");
  script_xref(name:"HP", value:"SSRT080059");
  script_xref(name:"HP", value:"SSRT080100");

  script_name(english:"HP-UX PHSS_38761 : s700_800 11.X OV NNM7.01 Intermediate Patch 12");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM7.01 Intermediate Patch 12 : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential security vulnerability has been identified
    with HP OpenView Network Node Manager (OV NNM). The
    vulnerability could be exploited remotely to create a
    Denial of Service (DoS). (HPSBMA02374 SSRT080046)

  - Potential security vulnerabilities have been identified
    with HP OpenView Network Node Manager (OV NNM). The
    vulnerabilities could be exploited remotely to allow
    execution of arbitrary code or unauthorized access to
    data. (HPSBMA02406 SSRT080100)

  - A potential security vulnerability has been identified
    with HP OpenView Network Node Manager (OV NNM). The
    vulnerability could be exploited remotely to create a
    Denial of Service (DoS). (HPSBMA02392 SSRT071481)

  - A potential vulnerability has been identified with HP
    OpenView Network Node Manager (OV NNM). The
    vulnerability could be exploited remotely execute
    arbitrary code or to create a Denial of Service (DoS).
    (HPSBMA02338 SSRT080024, SSRT080041)

  - Potential security vulnerabilities have been identified
    with HP OpenView Network Node Manager (OV NNM). The
    vulnerabilities could be exploited remotely to allow
    cross site scripting (XSS). (HPSBMA02388 SSRT080059)

  - Potential security vulnerabilities have been identified
    with HP OpenView Network Node Manager (OV NNM). The
    vulnerabilities could be exploited remotely to gain
    unauthorized access or to create a Denial of Service
    (DoS). References: CVE-2007-3698, CVE-2007-3922, SUN
    Alert 102995, 102997. (HPSBMA02384 SSRT071465)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01466051
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?202438e1"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01567813
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39f46ac2"
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
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01661610
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90fb6f0b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_38761 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 79, 119, 189, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/24");
  script_set_attribute(attribute:"patch_modification_date", value:"2008/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.00 11.11"))
{
  exit(0, "The host is not affected since PHSS_38761 applies to a different OS release.");
}

patches = make_list("PHSS_38761", "PHSS_40705");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-CORE", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-PD", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-PESA", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVMIB-CONTRIB", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNM-RUN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNMGR-JPN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNMGR-SCH", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVRPT-RUN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-JPN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-SCH", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgrMan.OVNNM-RUN-MAN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVDB-RUN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVEVENT-MIN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVMIN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVSNMP-MIN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWIN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-EVNT", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-FW", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-SRV", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVEVENTMIN-MAN", version:"B.07.01.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
