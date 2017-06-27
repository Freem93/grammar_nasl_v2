#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(34800);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/08/30 00:11:55 $");

  script_name(english:"Solaris 10 (x86) : 137138-09");
  script_summary(english:"Check for patch 137138-09");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 137138-09"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10_x86: kernel patch.
Date this patch was last updated by Sun : Nov/10/08"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/137138-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/17");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWnfssu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWcry", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWdmgtu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWypu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWpppd", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWiscsitgtu", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWxvmpv", version:"11.10.0,REV=2008.02.29.14.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWrsg", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWcryr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWahci", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWnfscu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWnfssr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWmdr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWxcu4", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWsshcu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWpcu", version:"13.1,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWlxu", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWrsgk", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWlxr", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWpmr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWos86r", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWiscsitgtr", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWsshdu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWipfh", version:"11.10.0,REV=2006.05.09.20.40") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWsshu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWsi3124", version:"11.10.0,REV=2006.03.27.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWmv88sx", version:"11.10.0,REV=2006.03.27.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWnfsskr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWipfu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWusb", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWnisu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWzoneu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"137138-09", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
