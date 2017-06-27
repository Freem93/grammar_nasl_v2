#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_30669. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(17068);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/04/20 00:41:02 $");

  script_cve_id("CVE-2004-0368");
  script_xref(name:"HP", value:"emr_na-c00957752");
  script_xref(name:"HP", value:"HPSBUX01038");
  script_xref(name:"HP", value:"SSRT4721");

  script_name(english:"HP-UX PHSS_30669 : HP-UX running CDE dtlogin, Remote Unauthorized Privileged Access, Denial of Service (DoS) (HPSBUX01038 SSRT4721 rev.2)");
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
running CDE dtlogin software, where the potential vulnerability may be
exploited locally or remotely to allow unauthorized privileged access
or a Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00957752
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20f68107"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_30669 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHSS_30669 applies to a different OS release.");
}

patches = make_list("PHSS_30669", "PHSS_30789", "PHSS_32111", "PHSS_32540", "PHSS_33326", "PHSS_34101", "PHSS_35434", "PHSS_36407");
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
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
