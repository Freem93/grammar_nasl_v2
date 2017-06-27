#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(23530);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/08/30 00:39:40 $");

  script_name(english:"Solaris 9 (sparc) : 116856-35");
  script_summary(english:"Check for patch 116856-35");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 116856-35"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Portal Server 6.2: Miscellaneous Fixes.
Date this patch was last updated by Sun : Mar/16/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/116856-35"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/16");
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

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsks", version:"6.2,REV=2003.11.17.14.13") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsnf", version:"6.2,REV=2003.11.17.14.20") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsmig", version:"6.2,REV=2003.11.17.14.07") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsrw", version:"6.2,REV=2003.11.17.13.48") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsp", version:"6.2,REV=2003.11.17.13.50") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpscp", version:"6.2,REV=2003.11.17.14.11") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsnl", version:"6.2,REV=2003.11.17.14.17") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsdtx", version:"6.2,REV=2003.11.17.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpssso", version:"6.2,REV=2003.11.17.14.10") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsgw", version:"6.2,REV=2003.11.17.14.14") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsdt", version:"6.2,REV=2003.11.17.13.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsgws", version:"6.2,REV=2003.11.17.14.14") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsrwp", version:"6.2,REV=2003.11.17.14.14") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsnm", version:"6.2,REV=2003.11.17.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWps", version:"6.2,REV=2003.11.17.14.07") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpssdk", version:"6.2,REV=2003.11.17.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsnlp", version:"6.2,REV=2003.11.17.14.17") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116856-35", obsoleted_by:"", package:"SUNWpsap", version:"6.2,REV=2003.11.17.14.11") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
