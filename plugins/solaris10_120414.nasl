#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(30165);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2014/08/30 00:06:18 $");

  script_name(english:"Solaris 10 (sparc) : 120414-27");
  script_summary(english:"Check for patch 120414-27");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 120414-27"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10: Asian CCK locales patch.
Date this patch was last updated by Sun : Mar/24/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/120414-27"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/24");
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

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120414-27", obsoleted_by:"", package:"SUNWhleu", version:"10.0,REV=2004.11.09.12.00") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120414-27", obsoleted_by:"", package:"SUNWhkplt", version:"10.0,REV=2004.11.09.12.00") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120414-27", obsoleted_by:"", package:"SUNWkxplt", version:"10.0,REV=2004.11.09.12.00") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120414-27", obsoleted_by:"", package:"SUNWhxplt", version:"10.0,REV=2004.11.09.12.00") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120414-27", obsoleted_by:"", package:"SUNWtxplt", version:"10.0,REV=2004.11.27.13.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120414-27", obsoleted_by:"", package:"SUNWcxplt", version:"10.0,REV=2004.11.09.12.03") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120414-27", obsoleted_by:"", package:"SUNWsunpinyin", version:"1.0.127,REV=10.0.3.2004.12.15.22.57") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120414-27", obsoleted_by:"", package:"SUNWhleu2", version:"10.0,REV=2004.11.09.12.00") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120414-27", obsoleted_by:"", package:"SUNWinleu", version:"10.0,REV=2004.11.09.12.06") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120414-27", obsoleted_by:"", package:"SUNWhkleu", version:"10.0,REV=2004.11.09.12.00") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120414-27", obsoleted_by:"", package:"SUNWkleu", version:"10.0,REV=2004.11.27.13.32") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120414-27", obsoleted_by:"", package:"SUNWinplt", version:"10.0,REV=2004.05.26.11.11") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120414-27", obsoleted_by:"", package:"SUNWtleu", version:"10.0,REV=2004.11.09.12.05") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
