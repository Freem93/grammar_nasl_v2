#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(71728);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/18 17:03:08 $");

  script_name(english:"Solaris 10 (x86) : 148580-08");
  script_summary(english:"Check for patch 148580-08");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 148580-08"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Instant Messaging 9.0_x86: security patch.
Date this patch was last updated by Sun : Oct/17/16"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/148580-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148580-08", obsoleted_by:"", package:"SUNWiimgw", version:"9.0,REV=2011.09.05") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148580-08", obsoleted_by:"", package:"SUNWiimfed", version:"9.0,REV=2011.09.05") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148580-08", obsoleted_by:"", package:"SUNWiimjd", version:"9.0,REV=2011.09.05") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148580-08", obsoleted_by:"", package:"SUNWiimw", version:"9.0,REV=2011.09.05") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148580-08", obsoleted_by:"", package:"SUNWiimid", version:"9.0,REV=2011.09.05") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148580-08", obsoleted_by:"", package:"SUNWiimin", version:"9.0,REV=2011.09.05") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148580-08", obsoleted_by:"", package:"SUNWiim", version:"9.0,REV=2011.09.05") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148580-08", obsoleted_by:"", package:"SUNWiimm", version:"9.0,REV=2011.09.05") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
