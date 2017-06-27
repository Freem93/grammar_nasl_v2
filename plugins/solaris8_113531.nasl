#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(23359);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/08/30 00:33:49 $");

  script_name(english:"Solaris 8 (sparc) : 113531-10");
  script_summary(english:"Check for patch 113531-10");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 113531-10"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PC NetLink 2.0 server fixes.
Date this patch was last updated by Sun : Feb/24/06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/113531-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/24");
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

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113531-10", obsoleted_by:"", package:"SUNWlzha", version:"2.0,REV=rr24") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113531-10", obsoleted_by:"", package:"SUNWlzs", version:"2.0,REV=rr24") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113531-10", obsoleted_by:"", package:"SUNWlzm", version:"2.0,REV=rr24") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
