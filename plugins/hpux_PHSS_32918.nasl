#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_32918. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(18349);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/04/20 00:41:03 $");

  script_xref(name:"HP", value:"emr_na-c01026698");
  script_xref(name:"HP", value:"SSRT4796");
  script_xref(name:"HP", value:"SSRT4873");

  script_name(english:"HP-UX PHSS_32918 : HP OpenView Event Correlation Services (OV ECS), Remote Unauthorized Privileged Code Execution, Denial of Service (DoS) (HPSBMA01141 SSRT4796, SSRT4873 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV ECS3.33 /3.32 Patch Mar'05 : 

Potential vulnerabilities have been identified with OpenView Event
Correlation Services (OV ECS). These vulnerabilities could be
exploited remotely by an unauthorized user to execute privileged code
or to cause a Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01026698
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8777208"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_32918 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/19");
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
  exit(0, "The host is not affected since PHSS_32918 applies to a different OS release.");
}

patches = make_list("PHSS_32918", "PHSS_33538", "PHSS_34634", "PHSS_37280");
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
