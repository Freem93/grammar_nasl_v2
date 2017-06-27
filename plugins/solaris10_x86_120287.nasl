#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(71821);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/30 00:11:54 $");

  script_name(english:"Solaris 10 (x86) : 120287-04");
  script_summary(english:"Check for patch 120287-04");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 120287-04"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNOME 2.6.0_x86: Gnome text editor Patch.
Date this patch was last updated by Sun : Jun/04/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/120287-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120287-04", obsoleted_by:"", package:"SUNWgnome-text-editor-root", version:"2.6.0,REV=10.0.3.2004.12.16.20.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120287-04", obsoleted_by:"", package:"SUNWgnome-text-editor-devel", version:"2.6.0,REV=10.0.3.2004.12.16.20.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120287-04", obsoleted_by:"", package:"SUNWgnome-text-editor", version:"2.6.0,REV=10.0.3.2004.12.16.20.03") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
