#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(41982);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/30 00:11:55 $");

  script_name(english:"Solaris 10 (x86) : 122471-05");
  script_summary(english:"Check for patch 122471-05");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 122471-05"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNOME 2.6.0_x86: GNOME Java Help Patch.
Date this patch was last updated by Sun : Jul/09/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/122471-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/06");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122471-05", obsoleted_by:"", package:"SUNWgnome-l10ndocument-sv", version:"2.6.0,REV=10.0.3.2004.12.16.20.33") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122471-05", obsoleted_by:"", package:"SUNWgnome-l10ndocument-ko", version:"2.6.0,REV=10.0.3.2004.12.16.20.33") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122471-05", obsoleted_by:"", package:"SUNWgnome-l10ndocument-zhCN", version:"2.6.0,REV=10.0.3.2004.12.16.20.33") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122471-05", obsoleted_by:"", package:"SUNWgnome-l10ndocument-fr", version:"2.6.0,REV=10.0.3.2004.12.16.20.32") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122471-05", obsoleted_by:"", package:"SUNWgnome-l10ndocument-de", version:"2.6.0,REV=10.0.3.2004.12.16.20.32") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122471-05", obsoleted_by:"", package:"SUNWgnome-l10ndocument-ptBR", version:"2.6.0,REV=10.0.3.2004.12.16.20.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122471-05", obsoleted_by:"", package:"SUNWgnome-l10ndocument-zhTW", version:"2.6.0,REV=10.0.3.2004.12.16.20.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122471-05", obsoleted_by:"", package:"SUNWgnome-l10ndocument-es", version:"2.6.0,REV=10.0.3.2004.12.16.20.32") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122471-05", obsoleted_by:"", package:"SUNWgnome-jdshelp", version:"2.6.0,REV=10.0.3.2004.12.16.19.02") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122471-05", obsoleted_by:"", package:"SUNWgnome-l10ndocument-ja", version:"2.6.0,REV=10.0.3.2004.12.16.20.33") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122471-05", obsoleted_by:"", package:"SUNWgnome-l10ndocument-zhHK", version:"2.6.0,REV=10.0.3.2004.12.16.20.33") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122471-05", obsoleted_by:"", package:"SUNWgnome-jdshelp-share", version:"2.6.0,REV=10.0.3.2004.12.16.19.02") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"122471-05", obsoleted_by:"", package:"SUNWgnome-l10ndocument-it", version:"2.6.0,REV=10.0.3.2004.12.16.20.33") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
