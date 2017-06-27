#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_27019. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17381);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/04/20 00:32:50 $");

  script_xref(name:"HP", value:"emr_na-c00958494");
  script_xref(name:"HP", value:"HPSBUX00275");
  script_xref(name:"HP", value:"SSRT3618");

  script_name(english:"HP-UX PHCO_27019 : HP-UX Shells, Local Increase of Privilege, Denial of Service (DoS) (HPSBUX00275 SSRT3618 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 ksh(1) patch : 

Shells improperly manage files during operations."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00958494
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?111eea64"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_27019 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");
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
  exit(0, "The host is not affected since PHCO_27019 applies to a different OS release.");
}

patches = make_list("PHCO_27019", "PHCO_30000", "PHCO_30316", "PHCO_33169", "PHCO_34509", "PHCO_36131", "PHCO_37283", "PHCO_38470");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.CORE-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-CORE", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
