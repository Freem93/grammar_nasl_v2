#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_28427. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17023);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/04/20 00:32:51 $");

  script_xref(name:"HP", value:"emr_na-c00908675");
  script_xref(name:"HP", value:"HPSBUX00310");
  script_xref(name:"HP", value:"SSRT2341");

  script_name(english:"HP-UX PHCO_28427 : HP-UX calloc(3C), Local Denial of Service (DoS) (HPSBUX00310 SSRT2341 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 libc cumulative patch : 

calloc miscalculates the memory requirements."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00908675
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4885a88e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_28427 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/29");
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
  exit(0, "The host is not affected since PHCO_28427 applies to a different OS release.");
}

patches = make_list("PHCO_28427", "PHCO_29029", "PHCO_29287", "PHCO_29495", "PHCO_29955", "PHCO_30030", "PHCO_30530", "PHCO_31061", "PHCO_31903", "PHCO_32761", "PHCO_33360", "PHCO_33533", "PHCO_33711", "PHCO_34275", "PHCO_35743", "PHCO_36184", "PHCO_37369", "PHCO_38279", "PHCO_40310");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.C-MIN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.C-MIN-64ALIB", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE-64SLIB", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE-SHLIBS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.SYS-ADMIN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG-AUX", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG-AX-64ALIB", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"ProgSupport.PROG-MIN", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
