#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(13741);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2014/08/30 00:39:40 $");

  script_name(english:"Solaris 9 (sparc) : 116340-09");
  script_summary(english:"Check for patch 116340-09");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 116340-09"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9: gzip and Freeware info files patch.
Date this patch was last updated by Sun : May/05/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/116340-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/23");
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

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116340-09", obsoleted_by:"", package:"SUNWsfinf", version:"11.9.0,REV=2002.03.02.00.35") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116340-09", obsoleted_by:"", package:"SUNWgzipS", version:"11.9.0,REV=2002.03.02.00.35") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116340-09", obsoleted_by:"", package:"SUNWgzip", version:"11.9.0,REV=2002.03.02.00.35") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
