#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(23583);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/08/30 00:45:32 $");

  script_name(english:"Solaris 9 (x86) : 116287-20");
  script_summary(english:"Check for patch 116287-20");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 116287-20"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun One Application Server 7.0_x86: Unbundled Core Patch.
Date this patch was last updated by Sun : May/23/06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/116287-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/23");
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

if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"116287-20", obsoleted_by:"", package:"SUNWasdmo", version:"7.0,REV=2003.10.10.14.34") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"116287-20", obsoleted_by:"", package:"SUNWasdvo", version:"7.0,REV=2003.10.10.14.34") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"116287-20", obsoleted_by:"", package:"SUNWaso", version:"7.0,REV=2003.10.10.14.34") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"116287-20", obsoleted_by:"", package:"SUNWascmo", version:"7.0,REV=2003.10.10.14.34") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"116287-20", obsoleted_by:"", package:"SUNWasro", version:"7.0,REV=2003.10.10.14.34") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"116287-20", obsoleted_by:"", package:"SUNWasaco", version:"7.0,REV=2003.10.10.14.34") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
