# @DEPRECATED@
#
# This script has been deprecated as the associated check has been
# entirely replaced by solaris10_148309.nasl.
#
# Disabled on 2015/05/22.
#

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(34798);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/22 18:07:17 $");

  script_name(english:"Solaris 10 (sparc) : 138876-01");
  script_summary(english:"Check for patch 138876-01");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 138876-01"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10: usr/lib/inet/in.dhcpd patch.
Date this patch was last updated by Sun : Nov/06/08"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/138876-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

# Deprecated.
exit(0, "The associated check has been entirely replaced by solaris10_148309.nasl.");


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"138876-01", obsoleted_by:"148309-03 ", package:"SUNWdhcsu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");