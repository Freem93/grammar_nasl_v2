#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_27850. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(16761);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/06/01 14:14:14 $");

  script_xref(name:"HP", value:"emr_na-c00959802");
  script_xref(name:"HP", value:"HPSBUX00208");
  script_xref(name:"HP", value:"SSRT071349");

  script_name(english:"HP-UX PHSS_27850 : HP-UX Running OpenView EMANATE14.2, Unauthorized Access or Denial of Service (DoS) (HPSBUX00208 SSRT071349 rev.4)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV EMANATE14.2 snmpdm - obsolete mib. : 

The HP OpenView EMANATE14.2 read-write community string may be
exposed."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00959802
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c2c2100"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_27850 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/09/16");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.00 11.11"))
{
  exit(0, "The host is not affected since PHSS_27850 applies to a different OS release.");
}

patches = make_list("PHSS_27850", "PHSS_27858", "PHSS_39886", "PHSS_41032", "PHSS_41556", "PHSS_42775", "PHSS_43156", "PHSS_43646", "PHSS_43817", "PHSS_44264");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVSNMPAgent.MASTER", version:"B.10.27.00")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.MASTER", version:"B.11.00.00")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.MASTER", version:"B.11.01.00")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.MASTER", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.MASTER", version:"B.11.11.00")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"B.10.27.00")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"B.11.00.00")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"B.11.01.00")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"B.11.11.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
