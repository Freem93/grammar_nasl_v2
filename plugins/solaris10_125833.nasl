#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(67146);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/30 00:06:18 $");

  script_name(english:"Solaris 10 (sparc) : 125833-05");
  script_summary(english:"Check for patch 125833-05");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 125833-05"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Management Center 3.6.1: SCM Patch for Solaris 10.
Date this patch was last updated by Sun : Jan/08/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/125833-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125833-05", obsoleted_by:"", package:"SUNWscma", version:"3.6.1,REV=2.10.2006.04.17") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125833-05", obsoleted_by:"", package:"SUNWscmcm", version:"3.6.1,REV=2.8.2006.04.17") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125833-05", obsoleted_by:"", package:"SUNWscmp", version:"3.6.1,REV=2.8.2006.04.17") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125833-05", obsoleted_by:"", package:"SUNWscmdb", version:"3.6.1,REV=2.8.2006.04.17") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125833-05", obsoleted_by:"", package:"SUNWscmh", version:"3.6.1,REV=2.8.2006.04.17") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125833-05", obsoleted_by:"", package:"SUNWscms", version:"3.6.1,REV=2.8.2006.04.17") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125833-05", obsoleted_by:"", package:"SUNWscmc", version:"3.6.1,REV=2.8.2006.04.17") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125833-05", obsoleted_by:"", package:"SUNWscmca", version:"3.6.1,REV=2.8.2006.04.17") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
