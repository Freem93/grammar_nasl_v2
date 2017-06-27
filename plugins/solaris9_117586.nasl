#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(30177);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/08/30 00:45:30 $");

  script_cve_id("CVE-2008-2945");

  script_name(english:"Solaris 9 (sparc) : 117586-22");
  script_summary(english:"Check for patch 117586-22");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 117586-22"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IS 6.1: Sun ONE Identity Server.
Date this patch was last updated by Sun : Jan/17/08"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/117586-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamwlp", version:"6.1,REV=03.11.20.11.52") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamsdk", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamsap", version:"6.1,REV=03.11.20.11.52") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamfcd", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamcon", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamsam", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamclt", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamsvc", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamwsc", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamsai", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamwli", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamsac", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWampwd", version:"6.1,REV=03.11.20.11.52") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamsas", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamsws", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamwsi", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamcds", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamwsp", version:"6.1,REV=03.11.20.11.52") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamwlc", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamrsa", version:"6.1,REV=03.11.20.11.51") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"117586-22", obsoleted_by:"", package:"SUNWamdsc", version:"6.1,REV=03.11.20.11.51") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
