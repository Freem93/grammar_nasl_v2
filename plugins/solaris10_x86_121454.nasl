#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(20381);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/08/30 00:11:54 $");

  script_name(english:"Solaris 10 (x86) : 121454-02");
  script_summary(english:"Check for patch 121454-02");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 121454-02"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10_x86: Sun Update Connection Client Foundation.
Date this patch was last updated by Sun : Dec/21/05"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/121454-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/04");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWccfwctrl", version:"1.0.0") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWccfw", version:"001.000.000") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWccinv", version:"1.0.0") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWdc", version:"1.0") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWppror", version:"5.0,REV=2005.01.09.21.19") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWccsign", version:"001.000.000") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWccccrr", version:"001.000.000") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWupdatemgrr", version:"0.1,REV=2005.05.20.11.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWcsmauth", version:"0.1,REV=2005.05.12.11.43") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWpprou", version:"5.0,REV=2005.01.09.21.19") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWbreg", version:"1.0") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWppro-plugin-sunos-base", version:"5.0,REV=2005.01.09.21.19") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWccccfg", version:"1.0.0") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWccccr", version:"001.000.000") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWcctpx", version:"001.000.000") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWswupcl", version:"1.0.3,REV=2005.06.23.09.01") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWupdatemgru", version:"0.1,REV=2005.05.20.11.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"121454-02", obsoleted_by:"", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
