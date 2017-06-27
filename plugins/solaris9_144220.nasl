#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(80884);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/21 15:43:59 $");

  script_name(english:"Solaris 9 (sparc) : 144220-15");
  script_summary(english:"Check for patch 144220-15");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 144220-15"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Solaris Cluster 3.2: CORE patch for Solaris 9.
Date this patch was last updated by Sun : Jan/20/15"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/144220-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"144220-15", obsoleted_by:"", package:"SUNWscrtlh", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"144220-15", obsoleted_by:"", package:"SUNWscmd", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"144220-15", obsoleted_by:"", package:"SUNWsczu", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"144220-15", obsoleted_by:"", package:"SUNWscdev", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"144220-15", obsoleted_by:"", package:"SUNWscucm", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"144220-15", obsoleted_by:"", package:"SUNWscu", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"144220-15", obsoleted_by:"", package:"SUNWscmasau", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"144220-15", obsoleted_by:"", package:"SUNWscr", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"144220-15", obsoleted_by:"", package:"SUNWsccomzu", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"144220-15", obsoleted_by:"", package:"SUNWsccomu", version:"3.2.0,REV=2006.12.05.22.50") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
