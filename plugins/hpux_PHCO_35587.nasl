#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_35587. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(26120);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/11 13:32:17 $");

  script_cve_id("CVE-2006-4334", "CVE-2006-4335", "CVE-2006-4336", "CVE-2006-4337", "CVE-2006-4338");
  script_bugtraq_id(19488, 20042);
  script_osvdb_id(29004, 29005, 29006, 29007, 29008);
  script_xref(name:"HP", value:"emr_na-c00874667");
  script_xref(name:"HP", value:"HPSBUX02195");
  script_xref(name:"HP", value:"SSRT061237");

  script_name(english:"HP-UX PHCO_35587 : HP-UX Running Software Distributor (SD), Remote Denial of Service (DoS) (HPSBUX02195 SSRT061237 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 Software Distributor Cumulative Patch : 

A potential security vulnerability has been identified with the
version of GZIP delivered by HP-UX Software Distributor (SD). The
vulnerability could be remotely exploited leading to a Denial of
Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00874667
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb18571d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_35587 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHCO_35587 applies to a different OS release.");
}

patches = make_list("PHCO_35587", "PHCO_38226", "PHCO_41200");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.GZIP", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FRE-I-MSG", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-GER-I-MSG", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-KOR-E-MSG", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-B-MSG", version:"B.11.11.0612.458")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0106")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0109")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0112")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0203")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0206")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0209")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0212")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0303")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0306")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0309")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0312")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0406")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0412")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0509.428")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-TCH-H-MSG", version:"B.11.11.0612.458")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
