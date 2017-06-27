#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(23360);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/08/30 00:33:49 $");

  script_name(english:"Solaris 8 (sparc) : 113800-12");
  script_summary(english:"Check for patch 113800-12");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 113800-12"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Cluster 3.1: Core/Sys Admin Patch.
Date this patch was last updated by Sun : May/18/04"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/113800-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/18");
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

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113800-12", obsoleted_by:"", package:"SUNWscu", version:"3.1.0,REV=2003.03.24.14.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113800-12", obsoleted_by:"", package:"SUNWscsal", version:"3.1.0,REV=2003.03.24.14.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113800-12", obsoleted_by:"", package:"SUNWscvw", version:"3.1.0,REV=2003.03.24.14.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113800-12", obsoleted_by:"", package:"SUNWscdev", version:"3.1.0,REV=2003.03.24.14.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113800-12", obsoleted_by:"", package:"SUNWscvr", version:"3.1.0,REV=2003.03.24.14.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113800-12", obsoleted_by:"", package:"SUNWscrif", version:"3.1.0,REV=2003.03.24.14.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113800-12", obsoleted_by:"", package:"SUNWscvm", version:"3.1.0,REV=2003.03.24.14.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113800-12", obsoleted_by:"", package:"SUNWscman", version:"3.1.0,REV=2003.03.24.14.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113800-12", obsoleted_by:"", package:"SUNWscsam", version:"3.1.0,REV=2003.03.24.14.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113800-12", obsoleted_by:"", package:"SUNWschwr", version:"3.1.0,REV=2003.03.24.14.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113800-12", obsoleted_by:"", package:"SUNWscr", version:"3.1.0,REV=2003.03.24.14.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"113800-12", obsoleted_by:"", package:"SUNWscrsm", version:"3.1.0,REV=2003.09.10.22.08") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
