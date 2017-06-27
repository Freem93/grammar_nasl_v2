#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(59050);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/30 00:06:20 $");

  script_name(english:"Solaris 10 (sparc) : 148002-01");
  script_summary(english:"Check for patch 148002-01");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 148002-01"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10: libdbus-1.so.3.4.2 patch.
Date this patch was last updated by Sun : May/04/12"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/148002-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"148002-01", obsoleted_by:"", package:"SUNWdbus-priv-libs", version:"1.2.12,REV=101.0.3") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"148002-01", obsoleted_by:"", package:"SUNWdbus-priv-devel", version:"1.2.12,REV=101.0.3") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"148002-01", obsoleted_by:"", package:"SUNWdbus-priv", version:"1.2.12,REV=101.0.3") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
