#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_40705. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(46261);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/18 20:51:41 $");

  script_cve_id("CVE-2008-0067", "CVE-2008-2438", "CVE-2009-0720", "CVE-2009-0898", "CVE-2009-0920", "CVE-2009-0921", "CVE-2009-3845", "CVE-2009-3846", "CVE-2009-3847", "CVE-2009-3848", "CVE-2009-3849", "CVE-2009-4176", "CVE-2009-4177", "CVE-2009-4178", "CVE-2009-4179", "CVE-2009-4180", "CVE-2009-4181", "CVE-2010-1550", "CVE-2010-1551", "CVE-2010-1552", "CVE-2010-1553", "CVE-2010-1554", "CVE-2010-1555");
  script_bugtraq_id(34738, 34812);
  script_osvdb_id(53218, 53219, 53220, 53221, 53222, 53242, 53243, 54107, 54222, 60923, 60924, 60925, 60926, 60927, 60928, 60929, 60930, 60931, 60932, 60933, 60934, 64973, 64974, 64975, 64976);
  script_xref(name:"HP", value:"emr_na-c01646081");
  script_xref(name:"HP", value:"emr_na-c01696729");
  script_xref(name:"HP", value:"emr_na-c01723303");
  script_xref(name:"HP", value:"emr_na-c01728300");
  script_xref(name:"HP", value:"emr_na-c01950877");
  script_xref(name:"HP", value:"emr_na-c02153379");
  script_xref(name:"HP", value:"SSRT010098");
  script_xref(name:"HP", value:"SSRT080091");
  script_xref(name:"HP", value:"SSRT080125");
  script_xref(name:"HP", value:"SSRT080144");
  script_xref(name:"HP", value:"SSRT090008");
  script_xref(name:"HP", value:"SSRT090257");

  script_name(english:"HP-UX PHSS_40705 : s700_800 11.11 OV NNM7.01 Intermediate Patch 13");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 OV NNM7.01 Intermediate Patch 13 : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential vulnerability has been identified with HP
    OpenView Network Node Manager (OV NNM). The
    vulnerability could be exploited remotely to execute
    arbitrary code. (HPSBMA02424 SSRT080125)

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
    with HP OpenView Network Node Manager (OV NNM). These
    vulnerabilities could be exploited remotely to allow
    execution of arbitrary code. (HPSBMA02400 SSRT080144)

  - Potential vulnerabilities have been identified with HP
    OpenView Network Node Manager (OV NNM). The
    vulnerabilities could be exploited remotely to execute
    arbitrary code. (HPSBMA02416 SSRT090008)

  - Potential security vulnerabilities have been identified
    with HP OpenView Network Node Manager (OV NNM). These
    vulnerabilities could be exploited remotely to execute
    arbitrary code. References: CVE-2010-1550 (SSRT090225,
    ZDI-CAN-563) CVE-2010-1551 (SSRT090226, ZDI-CAN-564)
    CVE-2010-1552 (SSRT090227, ZDI-CAN-566) CVE-2010-1553
    (SSRT090228, ZDI-CAN-573) CVE-2010-1554 (SSRT090229,
    ZDI-CAN-574) CVE-2010-1555 (SSRT090230, ZDI-CAN-575).
    (HPSBMA02527 SSRT010098)

  - A potential vulnerability has been identified with HP
    OpenView Network Node Manager (OV NNM). The
    vulnerability could be exploited remotely to execute
    arbitrary code. (HPSBMA02425 SSRT080091)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01646081
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdefacfb"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01696729
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed695dee"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01723303
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45827469"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01728300
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bbcab1d"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01950877
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?422f4693"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02153379
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5f413ca"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_40705 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP OpenView Network Node Manager getnnmdata.exe (Hostname) CGI Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/26");
  script_set_attribute(attribute:"patch_modification_date", value:"2010/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.11"))
{
  exit(0, "The host is not affected since PHSS_40705 applies to a different OS release.");
}

patches = make_list("PHSS_40705");
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
