#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_42328. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(56849);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2015/05/23 04:40:19 $");

  script_cve_id("CVE-2010-0738", "CVE-2011-1534", "CVE-2011-4155", "CVE-2011-4156", "CVE-2013-2351");
  script_bugtraq_id(47420, 50635, 61132);
  script_osvdb_id(64171, 71967, 76962, 76963, 95139);
  script_xref(name:"HP", value:"emr_na-c02788734");
  script_xref(name:"IAVB", value:"2013-B-0073");
  script_xref(name:"HP", value:"emr_na-c03035744");
  script_xref(name:"HP", value:"emr_na-c03057508");
  script_xref(name:"HP", value:"emr_na-c03747342");
  script_xref(name:"HP", value:"SSRT100244");
  script_xref(name:"HP", value:"SSRT100440");
  script_xref(name:"HP", value:"SSRT100633");

  script_name(english:"HP-UX PHSS_42328 : s700_800 11.X  OV NNM9.00 NNM 9.0x Patch 5");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM9.00 NNM 9.0x Patch 5 : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - Apotential security vulnerability has been identified
    with HP Network Node Manager I (NNMi) on HP-UX, Linux,
    Solaris, and Windows. The vulnerability could be
    remotely exploited resulting in unauthorized access.
    References: CVE-2013-2351 (SSRT101012, ZDI-CAN-1566).

  - A potential security vulnerability has been identified
    with HP Network Node Manager i (NNMi) for HP-UX, Linux,
    Solaris, and Windows. The vulnerability could be
    remotely exploited resulting in unauthorized disclosure
    of information. (HPSBMU02714 SSRT100244)

  - Potential security vulnerabilities have been identified
    with HP Network Node Manager i (NNMi) for HP-UX, Linux,
    Solaris, and Windows. The vulnerabilities could be
    remotely exploited resulting in cross site scripting
    (XSS). (HPSBMU02708 SSRT100633)

  - A potential vulnerability has been identified with HP
    Network Node Manager i (NNMi) for HP-UX, Linux, Solaris,
    and Windows. The vulnerability could be remotely
    exploited resulting in unauthorized access to NNMi
    processes. (HPSBMA02659 SSRT100440)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02788734
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7dec283b"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03035744
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8792dae1"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03057508
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85d28e00"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03747342
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54da22c0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_42328 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-132");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'JBoss JMX Console Deployer Upload and Execute');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/03");
  script_set_attribute(attribute:"patch_modification_date", value:"2011/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.23 11.31"))
{
  exit(0, "The host is not affected since PHSS_42328 applies to a different OS release.");
}

patches = make_list("PHSS_42328");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"HPOvNNM.HPNMSJBOSS", version:"9.00.000")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
