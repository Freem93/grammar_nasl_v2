#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(71704);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_name(english:"Solaris 10 (x86) : 143507-12");
  script_summary(english:"Check for patch 143507-12");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 143507-12"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNOME 2.6.0_x86: Python patch.
Date this patch was last updated by Sun : Apr/17/17"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/143507-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"143507-12", obsoleted_by:"", package:"SUNWPython-devel", version:"2.3.3,REV=10.0.3.2004.12.16.14.40") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"143507-12", obsoleted_by:"", package:"SUNWPython-sqlite", version:"2.6.4,REV=101.0.3.2012.02.10.10.24") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"143507-12", obsoleted_by:"", package:"SUNWPython", version:"2.3.3,REV=10.0.3.2004.12.16.14.40") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
