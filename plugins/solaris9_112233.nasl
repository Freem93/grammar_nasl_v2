#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(13510);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2014/08/30 00:39:38 $");

  script_name(english:"Solaris 9 (sparc) : 112233-12");
  script_summary(english:"Check for patch 112233-12");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 112233-12"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9: Kernel Patch.
Date this patch was last updated by Sun : Apr/21/04"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.oracle.com/sunalerts/1001080.1.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/21");
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

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWpiclu", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcstlx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcpcx", version:"11.9.0,REV=2002.04.09.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWusx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWhea", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWefclx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWnfscx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWarcx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWwrsux", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWfss", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcstl", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWncar", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWwrsmx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWged", version:"3.1,REV=2002.01.30.9.0") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcar", version:"11.9.0,REV=2002.04.09.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWpd", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcarx", version:"11.9.0,REV=2002.04.09.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWncaux", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"FJSVhea", version:"11.9.0,REV=2002.04.09.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWsxr", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWpdx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWdrr", version:"11.9.0,REV=2002.04.09.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWdrrx", version:"11.9.0,REV=2002.04.09.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWfssx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWefcux", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWwrsdx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWwrsax", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWmdbx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWidnx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWpmux", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWnisu", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcsxu", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWgedx", version:"3.1,REV=2002.01.30.9.0") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWpmu", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWgedu", version:"3.1,REV=2002.01.30.9.0") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcprx", version:"11.9.0,REV=2002.04.09.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWdrcrx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWnfscr", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWkvm", version:"11.9.0,REV=2002.04.09.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWncau", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcsu", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWefcx", version:"11.9.0,REV=2003.01.10.11.57") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcslx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcpc", version:"11.9.0,REV=2002.04.09.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWmdb", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcsr", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcpr", version:"11.9.0,REV=2002.04.09.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWcsl", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWarc", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWidn", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112233-12", obsoleted_by:"", package:"SUNWncarx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
