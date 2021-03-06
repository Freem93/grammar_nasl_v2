#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(67152);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/09/15 10:35:38 $");

  script_name(english:"Solaris 10 (x86) : 119118-54");
  script_summary(english:"Check for patch 119118-54");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119118-54"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Evolution 1.4.6_x86 patch.
Date this patch was last updated by Sun : Sep/13/14"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119118-54"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119118-54", obsoleted_by:"", package:"SUNWevolution-socs-connect", version:"1.0.0,REV=10.0.3.2004.12.16.17.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119118-54", obsoleted_by:"", package:"SUNWevolution", version:"1.4.6,REV=10.0.3.2004.12.16.17.01") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119118-54", obsoleted_by:"", package:"SUNWevolution-exchange", version:"1.4,REV=10.0.3.2004.12.16.17.02") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119118-54", obsoleted_by:"", package:"SUNWevolution-root", version:"1.4.6,REV=10.0.3.2004.12.16.17.01") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119118-54", obsoleted_by:"", package:"SUNWevolution-libs", version:"1.4.6,REV=10.0.3.2004.12.16.16.14") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119118-54", obsoleted_by:"", package:"SUNWevolution-share", version:"1.4.6,REV=10.0.3.2004.12.16.17.01") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
