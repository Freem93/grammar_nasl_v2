#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(49137);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/30 00:11:56 $");

  script_name(english:"Solaris 10 (x86) : 142910-17");
  script_summary(english:"Check for patch 142910-17");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 142910-17"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10_x86: kernel patch.
Date this patch was last updated by Sun : Sep/07/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/142910-17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWpsdcr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWpiclu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWcpcu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWnfssu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWcry", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWtavor", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWmrsas", version:"11.10.0,REV=2009.06.21.23.22") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWmegasas", version:"11.10.0,REV=2008.08.11.22.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWsndmr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWscpu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWsacom", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWfmdr", version:"11.10.0,REV=2006.03.29.01.57") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWtftp", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWftdur", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWsndmu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWxvmpv", version:"11.10.0,REV=2008.02.29.14.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWpool", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWpcmci", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWcryr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWxcu6", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWsshdr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWahci", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWnfscu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWpsdir", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWgrubS", version:"11.10.0,REV=2005.09.14.10.55") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWdcar", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWmdr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWrpcib", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWxcu4", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWsshcu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWpsm-ipp", version:"11.10.0.0,REV=2008.02.29.14.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWaccu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"BRCMbnx", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWpsu", version:"13.1,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWpapi", version:"11.10.0,REV=2005.01.08.01.09") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWcpc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWntxn", version:"11.10.0,REV=2009.02.23.22.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWigb", version:"11.10.0,REV=2008.02.29.14.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWio-tools", version:"11.10.0,REV=2009.06.25.23.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWpcu", version:"13.1,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWixgbe", version:"11.10.0,REV=2008.08.11.22.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWnge", version:"11.10.0,REV=2005.06.22.03.40") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWnxge", version:"11.10.0,REV=2007.07.08.17.21") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWlxu", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWopenssl-include", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWdtrp", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNW1394", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWaac", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWib", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWmptsas", version:"11.10.0,REV=2009.07.13.23.13") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWrsgk", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWzoner", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWses", version:"11.10.0,REV=2006.03.15.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWlxr", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWamd8111s", version:"11.10.0,REV=2006.11.06.19.53") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWrge", version:"11.10.0,REV=2006.03.27.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWos86r", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWnfscr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWsshdu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWrds", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWppm", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWxge", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWipoib", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWnv-sata", version:"11.10.1,REV=2008.08.11.22.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWhermon", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWsshu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWintgige", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWmv88sx", version:"11.10.0,REV=2006.03.27.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWgrub", version:"11.10.0,REV=2005.09.03.12.22") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWpcmem", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWnfsskr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWudapltu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWpsm-lpd", version:"11.10.0,REV=2005.01.08.01.09") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWypr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWusb", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWopenssl-commands", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWnisu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWixgb", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWhxge", version:"11.10.0,REV=2009.06.07.23.01") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWudfr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWzoneu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWudf", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"142910-17", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
