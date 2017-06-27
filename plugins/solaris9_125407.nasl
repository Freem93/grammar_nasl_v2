#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(27022);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/08/30 00:45:31 $");

  script_name(english:"Solaris 9 (sparc) : 125407-01");
  script_summary(english:"Check for patch 125407-01");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 125407-01"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Webservices 2.1: patch for Solaris 9 9_x86 10 10_x86.
Date this patch was last updated by Sun : Sep/05/07"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/125407-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"125407-01", obsoleted_by:"", package:"SUNWxwss", version:"2.0,REV=2006.09.28.03.41") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"125407-01", obsoleted_by:"", package:"SUNWjaxb2", version:"2.0.3,REV=2006.11.15.05.22") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"125407-01", obsoleted_by:"", package:"SUNWjaxws", version:"2.0,REV=2006.11.15.05.22") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
