#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(13295);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2014/08/30 00:17:44 $");

  script_name(english:"Solaris 8 (sparc) : 108528-29");
  script_summary(english:"Check for patch 108528-29");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 108528-29"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.8: kernel update  and Apache patch.
Date this patch was last updated by Sun : Feb/03/04"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/108528-29"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWpiclu", version:"11.8.0,REV=2000.08.15.00.06") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWtnfcx", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWtnfc", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWcstlx", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWcpcx", version:"11.8.0,REV=2000.01.13.13.40") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWapchu", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWusx", version:"11.8.0,REV=2000.07.05.13.22") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWhea", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWpiclx", version:"11.8.0,REV=2000.07.05.13.22") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWarcx", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWwrsux", version:"11.8.0,REV=2001.09.29.20.43") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWcstl", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWncar", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWwrsmx", version:"11.8.0,REV=2001.09.29.20.43") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWcar", version:"11.8.0,REV=2000.01.13.13.40") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWapchd", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"FJSVvplu", version:"11.7.0,REV=1999.12.23.19.10") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWcarx", version:"11.8.0,REV=2000.01.13.13.40") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWncaux", version:"11.8.0,REV=2000.04.01.16.21") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWapchS", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"FJSVhea", version:"1.0,REV=1999.12.23.19.10") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWsrh", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWdrr", version:"11.8.0,REV=2000.12.12.12.13") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWdrrx", version:"11.8.0,REV=2000.12.12.12.13") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"FJSVmdbx", version:"11.8.0,REV=2001.04.19.14.13") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWscpu", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWfruip", version:"11.8.0,REV=2001.01.19.01.02") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"FJSVpiclu", version:"11.8.0,REV=2002.10.24.16.51") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWwrsdx", version:"11.8.0,REV=2001.09.29.20.43") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWmdbx", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWidnx", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWpmux", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWpmr", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWcsxu", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWfruid", version:"11.8.0,REV=2001.01.19.01.02") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWpmu", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWcprx", version:"11.8.0,REV=2000.01.13.13.40") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"FJSVmdb", version:"11.8.0,REV=2001.04.19.14.13") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWapchr", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWpiclh", version:"11.8.0,REV=2000.07.05.13.22") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWkvm", version:"11.8.0,REV=2000.01.13.13.41") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWncau", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWcsu", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWcpc", version:"11.8.0,REV=2000.01.13.13.40") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWcslx", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWefcx", version:"11.8.0,REV=2000.10.03.21.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"FJSVvplr", version:"11.7.0,REV=1999.12.23.19.10") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWmdb", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWcpr", version:"11.8.0,REV=2000.01.13.13.40") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWcsr", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWcsl", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWarc", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWkvmx", version:"11.8.0,REV=2000.01.13.13.40") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWidn", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWncarx", version:"11.8.0,REV=2000.01.08.18.12") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", obsoleted_by:"", package:"SUNWfruix", version:"11.8.0,REV=2001.01.19.01.02") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
