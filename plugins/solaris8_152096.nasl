#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(90577);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_name(english:"Solaris 8 (sparc) : 152096-41");
  script_summary(english:"Check for patch 152096-41");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 152096-41"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"JavaSE 7: update 141 patch (equivalent to JDK 7u141).
Date this patch was last updated by Sun : Apr/17/17"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/152096-41"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"152096-41", obsoleted_by:"", package:"SUNWj7man", version:"1.7.0,REV=2011.06.27.06.20") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"152096-41", obsoleted_by:"", package:"SUNWj7cfg", version:"1.7.0,REV=2011.06.27.06.20") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"152096-41", obsoleted_by:"", package:"SUNWj7dmo", version:"1.7.0,REV=2011.06.27.06.20") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"152096-41", obsoleted_by:"", package:"SUNWj7dev", version:"1.7.0,REV=2011.06.27.06.20") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"152096-41", obsoleted_by:"", package:"SUNWj7jmp", version:"1.7.0,REV=2011.06.27.06.20") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"152096-41", obsoleted_by:"", package:"SUNWj7rt", version:"1.7.0,REV=2011.06.27.06.20") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
