#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_35434. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(22919);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/03/12 15:42:18 $");

  script_cve_id("CVE-2006-5452");
  script_osvdb_id(29974);
  script_xref(name:"HP", value:"emr_na-c00793091");
  script_xref(name:"HP", value:"HPSBUX02162");
  script_xref(name:"HP", value:"SSRT061223");

  script_name(english:"HP-UX PHSS_35434 : HP-UX Running dtmail, Local Execution of Arbitrary Code (HPSBUX02162 SSRT061223 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 CDE Applications Patch : 

A potential security vulnerability has been identified with HP-UX
running dtmail. The vulnerability could be exploited by a local,
authorized user to execute arbitrary code as a member of the 'mail'
group. References: NETRAGARD-20060810."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00793091
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f511d9dd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_35434 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_35434 applies to a different OS release.");
}

patches = make_list("PHSS_35434", "PHSS_36407");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"CDE.CDE-ENG-A-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-FONTS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-FRE-I-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-GER-I-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-HELP-RUN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-ITA-I-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-JPN-E-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-JPN-S-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-KOR-E-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-LANGS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-RUN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-SCH-H-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-SPA-I-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-SWE-I-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-TCH-B-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"CDE.CDE-TCH-E-HELP", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
