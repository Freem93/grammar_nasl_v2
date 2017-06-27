#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_28125. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17085);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/04/20 00:32:50 $");

  script_cve_id("CVE-2004-1375");
  script_xref(name:"HP", value:"emr_na-c00896487");
  script_xref(name:"HP", value:"HPSBUX01104");
  script_xref(name:"HP", value:"SSRT4699");

  script_name(english:"HP-UX PHCO_28125 : HP-UX Running System Administration Manager (SAM), Local Elevation of Privilege (HPSBUX01104 SSRT4699 rev.3)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 cumulative SAM/ObAM patch : 

A potential security vulnerability has been identified with System
Administration Manager (SAM) running on HP-UX that may allow local
unauthorized privileges."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00896487
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c12a1e08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_28125 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/06");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/03/22");
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
  exit(0, "The host is not affected since PHCO_28125 applies to a different OS release.");
}

patches = make_list("PHCO_28125", "PHCO_31879");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-BOOT", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"OS-Core.UX-CORE", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SystemAdmin.OBAM-RUN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SystemAdmin.SAM", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SystemAdmin.SAM-ENG-A-MAN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SystemAdmin.SAM-HELP", version:"B.11.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
