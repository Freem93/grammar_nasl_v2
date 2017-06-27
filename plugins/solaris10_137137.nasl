#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(34789);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/08/30 00:06:19 $");

  script_name(english:"Solaris 10 (sparc) : 137137-09");
  script_summary(english:"Check for patch 137137-09");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 137137-09"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10: kernel patch.
Date this patch was last updated by Sun : Nov/10/08"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/137137-09"
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

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWpiclu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWcpcu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWnfssu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWcry", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWtavor", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWdmgtu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWypu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWs9brandu", version:"11.10.0,REV=2008.04.24.03.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWpppd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWiscsitgtu", version:"11.10.0,REV=2007.06.20.13.33") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWssad", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWpmu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWefc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"FJSVvplr", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWrsg", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWcpr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"FJSVcpcu", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWnfscu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWnfssr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWust1", version:"11.10.0,REV=2005.08.10.02.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWmdr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWs9brandr", version:"11.10.0,REV=2008.04.24.03.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWus", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWmdu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWefcl", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWpd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWxcu4", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWsshcu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWkvmt200", version:"11.10.0,REV=2005.08.10.02.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWluxd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWldomu", version:"11.10.0,REV=2006.08.08.12.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"FJSVmdb", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWcart200", version:"11.10.0,REV=2005.08.10.02.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWpcu", version:"13.1,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWnxge", version:"11.10.0,REV=2007.07.08.17.44") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWs8brandu", version:"11.10.0,REV=2007.10.08.16.51") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"FJSVfmd", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWniumx", version:"11.10.0,REV=2007.06.20.13.33") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWs8brandr", version:"11.10.0,REV=2007.10.08.16.51") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWib", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWcar", version:"11.10.0,REV=2005.08.10.02.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWrsgk", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"FJSVhea", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWwbsup", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWpmr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"FJSVmdbr", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWiscsitgtr", version:"11.10.0,REV=2007.06.20.13.33") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWsshdu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWrds", version:"11.10.0,REV=2007.06.20.13.33") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWipfh", version:"11.10.0,REV=2006.05.09.21.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWiopc", version:"11.10.0,REV=2006.07.11.11.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWust2", version:"11.10.0,REV=2007.07.08.17.44") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWldomr", version:"11.10.0,REV=2006.10.04.00.26") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWpdu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWsshu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWnfsskr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWudapltu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWfruip", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"FJSVpiclu", version:"11.10.0,REV=2005.01.20.17.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWipfu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWusb", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWnisu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWkvm", version:"11.10.0,REV=2005.08.04.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWzoneu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137137-09", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.08.25.02.12") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
