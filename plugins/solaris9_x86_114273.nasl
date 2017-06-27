#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(13596);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2014/08/30 00:45:31 $");

  script_name(english:"Solaris 9 (x86) : 114273-04");
  script_summary(english:"Check for patch 114273-04");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 114273-04"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9_x86 5.10_x86: Sun ONE Directory Server 5.1 patch.
Date this patch was last updated by Sun : Mar/15/05"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/114273-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/15");
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

if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114273-04", obsoleted_by:"", package:"IPLTdsu", version:"5.1,REV=2002.03.01.12.34") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114273-04", obsoleted_by:"", package:"IPLTnls", version:"3.1,REV=2002.03.01.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114273-04", obsoleted_by:"", package:"IPLTjss", version:"3.1,REV=2002.03.01.12.34") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114273-04", obsoleted_by:"", package:"IPLTadcon", version:"5.1,REV=2002.03.01.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114273-04", obsoleted_by:"", package:"IPLTnss", version:"3.3.1,REV=2002.03.01.12.34") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114273-04", obsoleted_by:"", package:"IPLTpldap", version:"1.4.1,REV=2002.03.01.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114273-04", obsoleted_by:"", package:"IPLTcons", version:"5.1,REV=2002.03.01.12.30") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114273-04", obsoleted_by:"", package:"IPLTdscon", version:"5.1,REV=2002.03.01.12.30") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114273-04", obsoleted_by:"", package:"IPLTnspr", version:"4.1.2,REV=2002.03.01.12.37") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114273-04", obsoleted_by:"", package:"IPLTadmin", version:"5.1,REV=2002.03.01.12.29") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
