#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_30771. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(26140);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/04/20 00:41:02 $");

  script_xref(name:"HP", value:"emr_na-c00906162");
  script_xref(name:"HP", value:"HPSBUX00299");
  script_xref(name:"HP", value:"SSRT3660");

  script_name(english:"HP-UX PHSS_30771 : HP-UX Running DCE, Remote Denial of Service (DoS) (HPSBUX00299 SSRT3660 rev.4)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 HP DCE 1.9 client cumulative patch : 

Potential security vulnerability in DCE."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00906162
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4f37774"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_30771 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/22");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.23"))
{
  exit(0, "The host is not affected since PHSS_30771 applies to a different OS release.");
}

patches = make_list("PHSS_30771", "PHSS_33321", "PHSS_35466", "PHSS_36005", "PHSS_38258", "PHSS_42853");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"DCE-Core.DCE-COR-64SLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-COR-IA-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-COR-PA-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-CORE-DTS", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-CORE-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-CORE-SHLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-IA64-SHLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-CoreTools.DCE-BPRG", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
