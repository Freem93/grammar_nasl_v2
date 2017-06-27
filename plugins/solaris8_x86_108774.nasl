#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(13408);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2014/08/30 00:33:51 $");

  script_name(english:"Solaris 8 (x86) : 108774-28");
  script_summary(english:"Check for patch 108774-28");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 108774-28"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.8_x86: IIIM and X Input & Output Method patch.
Date this patch was last updated by Sun : May/27/08"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/108774-28"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWxim", version:"4.0,REV=1.0.38.1") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWxi18n", version:"4.0,REV=1.0.38.2") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWjpxpl", version:"1.2,REV=1999.12.08.15.55") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWiiimr", version:"1.0,REV=1.0.38.1") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWiiimu", version:"1.0,REV=1.0.38.1") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWjexpl", version:"1.0,REV=1999.12.08.15.55") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWjwncx", version:"1.2,REV=1999.12.24.12.19") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"JSatsvw", version:"1.0,REV=1999.12.08.12.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"108774-28", obsoleted_by:"", package:"SUNWjuxpl", version:"1.2,REV=1999.12.09.13.04") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
