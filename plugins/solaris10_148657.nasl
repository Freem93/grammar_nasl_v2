#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(58127);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/19 15:38:01 $");

  script_name(english:"Solaris 10 (sparc) : 148657-01 (deprecated)");
  script_summary(english:"Check for patch 148657-01");

  script_set_attribute(attribute:"synopsis", value:"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"SunOS 5.10: telnet patch. Date this patch was last updated by Sun :
Feb/21/12.

This plugin has been deprecated because the patch has been obsoleted
and no longer recommended.");
  script_set_attribute(attribute:"see_also", value:"https://getupdates.oracle.com/readme/148657-01");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/27");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

exit(0, 'This plugin has been deprecated since this patch has been obsoleted and is no longer recommended.');

include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"148657-01", obsoleted_by:"147793-16 ", package:"SUNWtnetc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
