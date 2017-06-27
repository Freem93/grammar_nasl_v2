#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(74086);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/20 14:24:50 $");

  script_name(english:"Solaris 10 (x86) : 151266-03");
  script_summary(english:"Check for patch 151266-03");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 151266-03"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunVTS 7.0_x86: Patch Set 18 consolidation.
Date this patch was last updated by Sun : Aug/15/14"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/151266-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"151266-03", obsoleted_by:"151673-01 ", package:"SUNWvts", version:"7.0,REV=2008.02.15.15.25") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"151266-03", obsoleted_by:"151673-01 ", package:"SUNWvtss", version:"7.0,REV=2008.02.07.18.55") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"151266-03", obsoleted_by:"151673-01 ", package:"SUNWvtsts", version:"7.0,REV=2008.02.15.15.25") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
