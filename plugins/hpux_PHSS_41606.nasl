#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_41606. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56843);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/03/12 15:42:19 $");

  script_cve_id("CVE-2010-2703", "CVE-2011-0261", "CVE-2011-0262", "CVE-2011-0263", "CVE-2011-0264", "CVE-2011-0265", "CVE-2011-0266", "CVE-2011-0267", "CVE-2011-0268", "CVE-2011-0269", "CVE-2011-0270", "CVE-2011-0271");
  script_bugtraq_id(41829);
  script_osvdb_id(66514, 70470, 70471, 70472, 70473, 70474, 70475);
  script_xref(name:"HP", value:"emr_na-c02286088");
  script_xref(name:"HP", value:"emr_na-c02670501");
  script_xref(name:"HP", value:"SSRT100025");
  script_xref(name:"HP", value:"SSRT100352");

  script_name(english:"HP-UX PHSS_41606 : s700_800 11.X OV NNM7.53 PA-RISC Intermediate Patch 28");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM7.53 PA-RISC Intermediate Patch 28 : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential vulnerability has been identified with HP
    OpenView Network Node Manager (OV NNM) running on
    Windows. The vulnerability could be exploited remotely
    to execute arbitrary code. References: CVE-2010-2703,
    ZDI-CAN-682. (HPSBMA02557 SSRT100025)

  - Potential security vulnerabilities have been identified
    with HP OpenView Network Node Manager (OV NNM). The
    vulnerabilities could be exploited remotely to execute
    arbitrary code under the context of the user running the
    web server. References: CVE-2011-0261 (ZDI-CAN-753)
    CVE-2011-0262 (ZDI-CAN-757) CVE-2011-0263 (ZDI-CAN-774)
    CVE-2011-0264 (ZDI-CAN-810) CVE-2011-0265 (ZDI-CAN-931)
    CVE-2011-0266 (ZDI-CAN-932) CVE-2011-0267 (ZDI-CAN-933)
    CVE-2011-0268 (ZDI-CAN-934) CVE-2011-0269 (ZDI-CAN-935)
    CVE-2011-0270 (ZDI-CAN-936) CVE-2011-0271 (iDefense).
    (HPSBMA02621 SSRT100352)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02286088
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dae68cca"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02670501
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e3effcb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_41606 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP OpenView NNM nnmRptConfig.exe schdParams Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/20");
  script_set_attribute(attribute:"patch_modification_date", value:"2011/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_41606 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_41606", "PHSS_41857", "PHSS_42232", "PHSS_43046", "PHSS_43353");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVNNMgrRtDOC.OVNNM-KOR-DOC", version:"B.07.50.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
