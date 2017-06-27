#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(13511);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/08/30 00:39:38 $");

  script_name(english:"Solaris 9 (sparc) : 112601-10");
  script_summary(english:"Check for patch 112601-10");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 112601-10"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9: PGX32 Graphics.
Date this patch was last updated by Sun : Feb/15/06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/112601-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/15");
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

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112601-10", obsoleted_by:"", package:"TSIpgxx", version:"9.0.0,REV=2002.01.15") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112601-10", obsoleted_by:"", package:"TSIpgx", version:"9.0.0,REV=2002.01.15") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112601-10", obsoleted_by:"", package:"TSIpgxw", version:"9.0.0,REV=2002.01.15") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
