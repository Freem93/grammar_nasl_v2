#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(23403);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/08/30 00:33:50 $");

  script_name(english:"Solaris 8 (sparc) : 118128-13");
  script_summary(english:"Check for patch 118128-13");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 118128-13"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PS 6.3.1: Portal Server.
Date this patch was last updated by Sun : Feb/18/05"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/118128-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/18");
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

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpssp", version:"6.2,REV=2003.11.17.14.09") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsps", version:"6.2,REV=2003.11.17.13.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsks", version:"6.2,REV=2003.11.17.14.13") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsnf", version:"6.2,REV=2003.11.17.14.20") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsmig", version:"6.2,REV=2003.11.17.14.07") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpswsrpproducersample", version:"6.3,REV=2004.05.07.19.35") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsss", version:"6.2,REV=2003.11.17.14.21") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsrw", version:"6.2,REV=2003.11.17.13.48") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpspltconfig", version:"6.3,REV=2004.05.07.19.35") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsdtm", version:"6.2,REV=2003.11.17.13.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpswsrpcommon", version:"6.3,REV=2004.05.07.19.09") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsp", version:"6.2,REV=2003.11.17.13.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpscp", version:"6.2,REV=2003.11.17.14.11") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpswsrpconsumersample", version:"6.3,REV=2004.05.07.19.35") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsnl", version:"6.2,REV=2003.11.17.14.17") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsdtx", version:"6.2,REV=2003.11.17.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsc", version:"6.2,REV=2003.11.17.13.48") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpssso", version:"6.2,REV=2003.11.17.14.10") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsoh", version:"6.2,REV=2003.11.17.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsgw", version:"6.2,REV=2003.11.17.14.14") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsmp", version:"6.2,REV=2003.11.17.14.11") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsgwm", version:"6.2,REV=2003.11.17.14.15") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsdis", version:"6.2,REV=2003.11.17.14.09") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsdt", version:"6.2,REV=2003.11.17.13.49") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsgws", version:"6.2,REV=2003.11.17.14.14") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsse", version:"6.2,REV=2003.11.17.14.02") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpssub", version:"6.2,REV=2003.11.17.14.09") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsrwp", version:"6.2,REV=2003.11.17.14.14") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsssoa", version:"6.3,REV=2004.05.07.19.19") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsplt", version:"6.3,REV=2004.05.07.19.35") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWiimps", version:"6.2,REV=2003.11.17.14.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpswsrpproducer", version:"6.3,REV=2004.05.07.19.13") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsnm", version:"6.2,REV=2003.11.17.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsgwa", version:"6.2,REV=2003.11.17.14.14") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpssep", version:"6.2,REV=2003.11.17.14.02") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpssea", version:"6.2,REV=2003.11.17.14.02") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWps", version:"6.2,REV=2003.11.17.14.07") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpswsrpconsumer", version:"6.3,REV=2004.05.07.19.10") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsrwa", version:"6.2,REV=2003.11.17.13.48") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpssdk", version:"6.2,REV=2003.11.17.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpscfg", version:"6.2,REV=2003.11.17.14.22") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsnlp", version:"6.2,REV=2003.11.17.14.17") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsdta", version:"6.2,REV=2003.11.17.13.50") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"118128-13", obsoleted_by:"", package:"SUNWpsap", version:"6.2,REV=2003.11.17.14.11") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
