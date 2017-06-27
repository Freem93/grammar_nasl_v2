#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(23000);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2014/08/30 00:11:55 $");

  script_cve_id("CVE-2006-3404");

  script_name(english:"Solaris 10 (x86) : 122213-46");
  script_summary(english:"Check for patch 122213-46");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 122213-46"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNOME 2.6.0_x86: GNOME Desktop Patch.
Date this patch was last updated by Sun : Nov/10/12"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/122213-46"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/10");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-file-mgr-root", version:"2.6.0,REV=10.0.3.2004.12.16.17.52") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-libs-share", version:"2.6.0,REV=10.0.3.2004.12.16.15.52") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-session", version:"2.6.0,REV=10.0.3.2004.12.21.12.59") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-display-mgr-root", version:"2.6.0,REV=10.0.3.2004.12.16.18.45") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-display-mgr", version:"2.6.0,REV=10.0.3.2004.12.16.18.45") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-panel-root", version:"2.6.0,REV=10.0.3.2004.12.16.17.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-panel-share", version:"2.6.0,REV=10.0.3.2004.12.16.17.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-libs-root", version:"2.6.0,REV=10.0.3.2004.12.16.15.52") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-libs-devel", version:"2.6.0,REV=10.0.3.2004.12.16.15.52") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-desktop-prefs", version:"2.6.0,REV=10.0.3.2004.12.21.13.11") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-img-editor", version:"2.6.0,REV=10.0.3.2004.12.16.18.25") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-img-viewer-share", version:"2.6.0,REV=10.0.3.2004.12.16.19.00") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-themes-share", version:"2.6.0,REV=10.0.3.2004.12.16.15.58") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWPython", version:"2.3.3,REV=10.0.3.2004.12.16.14.40") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-session-share", version:"2.6.0,REV=10.0.3.2004.12.21.12.59") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-libs", version:"2.6.0,REV=10.0.3.2004.12.16.15.52") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-file-mgr-share", version:"2.6.0,REV=10.0.3.2004.12.16.17.52") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-desktop-prefs-share", version:"2.6.0,REV=10.0.3.2004.12.21.13.11") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-display-mgr-share", version:"2.6.0,REV=10.0.3.2004.12.16.18.45") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-panel-devel", version:"2.6.0,REV=10.0.3.2004.12.16.17.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-panel", version:"2.6.0,REV=10.0.3.2004.12.16.17.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-file-mgr", version:"2.6.0,REV=10.0.3.2004.12.16.17.52") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122213-46", obsoleted_by:"", package:"SUNWgnome-img-editor-share", version:"2.6.0,REV=10.0.3.2004.12.16.18.25") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
