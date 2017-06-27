#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_41201. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49112);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/03/12 15:37:24 $");

  script_cve_id("CVE-2010-2712");
  script_bugtraq_id(42755);
  script_osvdb_id(67537);
  script_xref(name:"HP", value:"emr_na-c02285980");
  script_xref(name:"HP", value:"HPSBUX02552");
  script_xref(name:"HP", value:"SSRT100062");

  script_name(english:"HP-UX PHCO_41201 : HP-UX running Software Distributor (sd), Local Privilege Increase, Unauthorized Access (HPSBUX02552 SSRT100062 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 Software Distributor Cumulative Patch : 

A potential security vulnerability has been identified with HP-UX
running Software Distributor (sd). The vulnerability could be
exploited locally to grant an increase in privilege, or to permit
unauthorized access."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02285980
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b2d4e79"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_41201 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHCO_41201 applies to a different OS release.");
}

patches = make_list("PHCO_41201");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP2", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-PROVIDER", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-AGENT", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-CMDS", version:"B.11.23.1009.352")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0403.3")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0409")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0505.018")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0512.033")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0603.039")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0606.045")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0609.052")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0612.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0706.063")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0712.069")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0803.317")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0803.318")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0809.325")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0903.332")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.0909.340")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.1003.346")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD2-PROVIDER", version:"B.11.23.1009.352")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
