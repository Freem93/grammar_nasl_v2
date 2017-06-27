#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_27639. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(17482);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/04/20 00:36:50 $");

  script_xref(name:"HP", value:"emr_na-c00904239");
  script_xref(name:"HP", value:"HPSBUX00197");
  script_xref(name:"HP", value:"SSRT2332");

  script_name(english:"HP-UX PHSS_27639 : HP-UX Running Apache, Remote Denial of Service (DoS) or Elevation Privilege, or Execution of Arbitrary Code (HPSBUX00197 SSRT2332 rev.11)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM6.2 http server fix : 

A potential remotely exploitable vulnerability in handling of large
data chunks in Apache-based web servers."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00904239
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c581f274"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_27639 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/05");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/03/22");
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

if (!hpux_check_ctx(ctx:"11.00 11.11"))
{
  exit(0, "The host is not affected since PHSS_27639 applies to a different OS release.");
}

patches = make_list("PHSS_27639", "PHSS_27747", "PHSS_27836", "PHSS_27917", "PHSS_28092", "PHSS_28095", "PHSS_28258", "PHSS_28348", "PHSS_28400", "PHSS_28473", "PHSS_28546", "PHSS_28587", "PHSS_28705", "PHSS_28878", "PHSS_29206", "PHSS_29429", "PHSS_29754", "PHSS_30104", "PHSS_30419", "PHSS_31185", "PHSS_32046", "PHSS_32690", "PHSS_33287", "PHSS_34008", "PHSS_35113");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVPlatform.OVWWW-SRV", version:"B.06.20.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
