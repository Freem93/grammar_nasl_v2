#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(41952);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/30 00:06:18 $");

  script_name(english:"Solaris 10 (sparc) : 120460-21");
  script_summary(english:"Check for patch 120460-21");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 120460-21"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNOME 2.6.0: GNOME libs Patch.
Date this patch was last updated by Sun : May/30/13"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/120460-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120460-21", obsoleted_by:"", package:"SUNWgnome-base-libs-devel", version:"2.6.0,REV=10.0.3.2004.12.15.15.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120460-21", obsoleted_by:"", package:"SUNWgnome-base-libs-root", version:"2.6.0,REV=10.0.3.2004.12.15.15.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120460-21", obsoleted_by:"", package:"SUNWgnome-base-libs-devel-share", version:"2.6.0,REV=10.0.3.2004.12.15.15.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120460-21", obsoleted_by:"", package:"SUNWgnome-base-libs-share", version:"2.6.0,REV=10.0.3.2004.12.15.15.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120460-21", obsoleted_by:"", package:"SUNWgnome-base-libs", version:"2.6.0,REV=10.0.3.2004.12.15.15.24") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
