#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(36541);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/30 00:06:18 $");

  script_name(english:"Solaris 10 (sparc) : 120650-01");
  script_summary(english:"Check for patch 120650-01");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 120650-01"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun StorEdge EBS 7.2: Product Patch SU1.
Date this patch was last updated by Sun : Jan/27/06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/120650-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120650-01", obsoleted_by:"116831-03 ", package:"SUNWebsc", version:"7.2,REV=172") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120650-01", obsoleted_by:"116831-03 ", package:"SUNWebsn", version:"7.2,REV=172") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120650-01", obsoleted_by:"116831-03 ", package:"SUNWebss", version:"7.2,REV=172") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120650-01", obsoleted_by:"116831-03 ", package:"SUNWebsd", version:"7.2,REV=172") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120650-01", obsoleted_by:"116831-03 ", package:"SUNWebsm", version:"7.2,REV=172") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
