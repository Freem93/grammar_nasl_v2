#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(19843);
  script_version("$Revision: 1.43 $");
  script_cvs_date("$Date: 2014/08/30 00:45:32 $");

  script_cve_id("CVE-2006-5012");

  script_name(english:"Solaris 9 (x86) : 118559-39");
  script_summary(english:"Check for patch 118559-39");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 118559-39"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9_x86: Kernel Patch.
Date this patch was last updated by Sun : Jan/17/07"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/118559-39"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118559-39", obsoleted_by:"", package:"SUNWmdr", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118559-39", obsoleted_by:"", package:"SUNWhea", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118559-39", obsoleted_by:"", package:"SUNWmdu", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118559-39", obsoleted_by:"", package:"SUNWcar", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118559-39", obsoleted_by:"", package:"SUNWmdau", version:"11.9.0,REV=2003.10.17.13.30") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118559-39", obsoleted_by:"", package:"SUNWrmodr", version:"11.9.0,REV=2002.10.02.19.20") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118559-39", obsoleted_by:"", package:"SUNWos86r", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118559-39", obsoleted_by:"", package:"SUNWkvm", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118559-39", obsoleted_by:"", package:"SUNWcsu", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118559-39", obsoleted_by:"", package:"SUNWmdb", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118559-39", obsoleted_by:"", package:"SUNWcsr", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118559-39", obsoleted_by:"", package:"SUNWcsl", version:"11.9.0,REV=2002.11.04.02.51") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"118559-39", obsoleted_by:"", package:"SUNWmddr", version:"11.9.0,REV=2002.10.31.12.55") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
