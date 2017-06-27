#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_25138. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(16966);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/04/20 00:36:50 $");

  script_xref(name:"HP", value:"emr_na-c00994228");
  script_xref(name:"HP", value:"HPSBUX00168");
  script_xref(name:"HP", value:"SSRT071383");

  script_name(english:"HP-UX PHSS_25138 : HP-UX running rpc.ttdbserverd, Remote Unauthorized Access, Increased Privilege (HPSBUX00168 SSRT071383 rev.5)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 CDE Runtime SEP2001 Periodic Patch : 

Buffer overflow in rpc.ttdbserver."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00994228
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8f258e0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_25138 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/10/01");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/04/19");
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

if (!hpux_check_ctx(ctx:"11.00"))
{
  exit(0, "The host is not affected since PHSS_25138 applies to a different OS release.");
}

patches = make_list("PHSS_25138", "PHSS_25194", "PHSS_25787", "PHSS_26490", "PHSS_27427", "PHSS_27869", "PHSS_28675", "PHSS_29734", "PHSS_30010", "PHSS_30668", "PHSS_32107", "PHSS_32539", "PHSS_35433");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"CDE.CDE-DTTERM", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"CDE.CDE-ENG-A-HELP", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"CDE.CDE-ENG-A-MAN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"CDE.CDE-ENG-A-MSG", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"CDE.CDE-FONTS", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"CDE.CDE-HELP-RUN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"CDE.CDE-MIN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"CDE.CDE-RUN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"CDE.CDE-SHLIBS", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"CDE.CDE-TT", version:"B.11.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
