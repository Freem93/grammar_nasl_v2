# @DEPRECATED@
#
# This script has been deprecated as the associated patch is no
# longer available from Oracle.
#
# Disabled on 2015/04/20.

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(23393);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/20 14:32:45 $");

  script_name(english:"Solaris 8 (sparc) : 117367-02");
  script_summary(english:"Check for patch 117367-02");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 117367-02"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Enterprise Storage Manager 2.1 SAN Manager management station patc.
Date this patch was last updated by Sun : Oct/06/04"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/117367-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is no longer available from Oracle.");

include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117367-02", obsoleted_by:"", package:"SUNWstui", version:"2.1.0 ,REV=04.15.04") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117367-02", obsoleted_by:"", package:"SUNWstmsu", version:"2.1.0 ,REV=04.15.04") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"117367-02", obsoleted_by:"", package:"SUNWstoba", version:"2.1.0 ,REV=04.15.04") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
