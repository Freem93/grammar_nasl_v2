#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_33539. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(19824);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2014/03/12 15:42:17 $");

  script_osvdb_id(19864);
  script_xref(name:"HP", value:"emr_na-c01026449");
  script_xref(name:"HP", value:"SSRT051030");

  script_name(english:"HP-UX PHSS_33539 : HP OpenView Event Correlation Services (OV ECS), Remote Unauthorized Privileged Access (HPSBMA01225 SSRT051030 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 OV ECS3.33 IA-64 Consolidated Patch : 

A potential vulnerability has been identified with HP OpenView Event
Correlation Services (OV ECS). This vulnerability could be exploited
remotely by an unauthorized user to gain privileged access."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01026449
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81e2452f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_33539 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.23", proc:"ia64"))
{
  exit(0, "The host is not affected since PHSS_33539 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_33539", "PHSS_34635", "PHSS_37281");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVECS.OVECS-CMG", version:"A.03.32")) flag++;
if (hpux_check_patch(app:"OVECS.OVECS-CMG", version:"A.03.33")) flag++;
if (hpux_check_patch(app:"OVECS.OVECS-RUN", version:"A.03.32")) flag++;
if (hpux_check_patch(app:"OVECS.OVECS-RUN", version:"A.03.33")) flag++;
if (hpux_check_patch(app:"OVECS.OVECS-RUN-JPN", version:"A.03.32")) flag++;
if (hpux_check_patch(app:"OVECS.OVECS-RUN-JPN", version:"A.03.33")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
