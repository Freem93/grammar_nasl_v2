#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_24091. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17462);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/04/30 10:47:12 $");

  script_xref(name:"HP", value:"emr_na-c00994219");
  script_xref(name:"HP", value:"HPSBUX00151");
  script_xref(name:"HP", value:"SSRT071382");

  script_name(english:"HP-UX PHSS_24091 : HP-UX running CDE, Local Increased Privilege, Denial of Service (DoS) (HPSBUX00151 SSRT071382 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 CDE Base APR2001 Periodic Patch : 

Buffer overflows and other vulnerabilities in CDE for HP-UX."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00994219
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d6c183f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_24091 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/19");
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
  exit(0, "The host is not affected since PHSS_24091 applies to a different OS release.");
}

patches = make_list("PHSS_24091", "PHSS_25139", "PHSS_25196", "PHSS_25788", "PHSS_26492", "PHSS_27428", "PHSS_27872", "PHSS_28676", "PHSS_29735", "PHSS_30011", "PHSS_30788", "PHSS_32110", "PHSS_33325", "PHSS_35249", "PHSS_36394", "PHSS_43518");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"CDE.CDE-SHLIBS", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
