#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(23510);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/08/30 00:39:39 $");

  script_name(english:"Solaris 9 (sparc) : 115738-06");
  script_summary(english:"Check for patch 115738-06");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 115738-06"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNOME 2.0.2: Base GUI Libraries Patch.
Date this patch was last updated by Sun : Mar/07/08"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/115738-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115738-06", obsoleted_by:"", package:"SUNWgnome-base-libs", version:"2.0.2,REV=9.4.2003.05.14.06.42") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115738-06", obsoleted_by:"", package:"SUNWgnome-base-libs-64-root", version:"2.0.2,REV=9.4.2003.05.14.06.42") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115738-06", obsoleted_by:"", package:"SUNWgnome-base-libs-root", version:"2.0.2,REV=9.4.2003.05.14.06.42") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"115738-06", obsoleted_by:"", package:"SUNWgnome-base-libs-64", version:"2.0.2,REV=9.4.2003.05.14.06.42") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
