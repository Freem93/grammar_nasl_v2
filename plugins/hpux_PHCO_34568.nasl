#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_34568. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(21650);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/03/12 15:37:23 $");

  script_cve_id("CVE-2006-2574");
  script_osvdb_id(25804);
  script_xref(name:"HP", value:"emr_na-c00659649");
  script_xref(name:"HP", value:"HPSBUX02114");
  script_xref(name:"HP", value:"SSRT061115");

  script_name(english:"HP-UX PHCO_34568 : HP-UX Running Software Distributor Local Elevation of Privilege (HPSBUX02114 SSRT061115 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 Software Distributor (SD) Cumulative Patch : 

Potential security vulnerabilities have been identified with HP-UX
running Software Distributor. These vulnerabilities could be exploited
by a local authorized user to gain elevated privileges."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00659649
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec9c4710"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_34568 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHCO_34568 applies to a different OS release.");
}

patches = make_list("PHCO_34568");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.00.05.01")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
