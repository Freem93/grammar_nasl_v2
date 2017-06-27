#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(40937);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/30 00:06:19 $");

  script_name(english:"Solaris 10 (sparc) : 142189-01");
  script_summary(english:"Check for patch 142189-01");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 142189-01"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"StarSuite 9 (Solaris): Update 3 (requires Update 2).
Date this patch was last updated by Sun : Sep/09/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/142189-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/11");
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

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-core04", version:"3.1.0,REV=11.2009.04.23") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-zh-CN-res", version:"3.1.0,REV=11.2009.04.23") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-core01", version:"3.1.0,REV=11.2009.04.23") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-zh-TW-res", version:"3.1.0,REV=11.2009.04.23") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-calc", version:"3.1.0,REV=11.2009.04.23") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-ko-res", version:"3.1.0,REV=11.2009.04.23") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-en-US-res", version:"3.1.0,REV=11.2009.04.23") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-core05", version:"3.1.0,REV=11.2009.04.23") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-ja-res", version:"3.1.0,REV=11.2009.04.23") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"openofficeorg-ure", version:"1.5.0,REV=11.2009.04.23") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"142189-01", obsoleted_by:"", package:"ooobasis31-writer", version:"3.1.0,REV=11.2009.04.23") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
