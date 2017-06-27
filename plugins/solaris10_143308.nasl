#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(71818);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/30 00:06:19 $");

  script_name(english:"Solaris 10 (sparc) : 143308-03");
  script_summary(english:"Check for patch 143308-03");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 143308-03"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Solaris Cluster Geographic Edition 3.2 11/09: Core, Utilities & Ma.
Date this patch was last updated by Sun : Sep/14/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/143308-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"143308-03", obsoleted_by:"", package:"SUNWscgctl", version:"3.2.3,REV=2009.10.23.12.12") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"143308-03", obsoleted_by:"", package:"SUNWscgrepodgu", version:"3.2.3,REV=2009.10.23.12.12") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"143308-03", obsoleted_by:"", package:"SUNWscghb", version:"3.2.3,REV=2009.10.23.12.12") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"143308-03", obsoleted_by:"", package:"SUNWscgrepsbpu", version:"3.2.3,REV=2009.10.23.12.12") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"143308-03", obsoleted_by:"", package:"SUNWscgrepodg", version:"3.2.3,REV=2009.10.23.12.12") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
