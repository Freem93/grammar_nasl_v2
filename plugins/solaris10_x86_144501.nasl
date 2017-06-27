#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(56436);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2011-3542");

  script_name(english:"Solaris 10 (x86) : 144501-19");
  script_summary(english:"Check for patch 144501-19");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 144501-19"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10_x86: Solaris kernel patch.
Date this patch was last updated by Sun : Aug/04/11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/144501-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWpsdcr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWpiclu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWcpcu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWnfssu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWcry", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWtavor", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWamr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWdmgtu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWipplu", version:"13.1,REV=2005.01.08.01.09") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWypu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWkdcu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWkrbr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWscsa1394", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWlsimega", version:"11.10.0,REV=2005.09.15.00.24") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWbcmsata", version:"11.10.0,REV=2010.07.14.14.54") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWmrsas", version:"11.10.0,REV=2009.06.21.23.22") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"CPQary3", version:"11.10.0,REV=2010.07.14.14.54") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWmegasas", version:"11.10.0,REV=2008.08.11.22.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWscpu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWkrbu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWfmdr", version:"11.10.0,REV=2006.03.29.01.57") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWiscsitgtu", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWpmu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWsndmu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWsmpd", version:"11.10.0,REV=2008.08.11.22.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWxvmpv", version:"11.10.0,REV=2008.02.29.14.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWpool", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWrdsv3", version:"11.10.0,REV=2010.07.14.14.54") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"BRCMbnxe", version:"11.10.0,REV=2010.07.14.14.54") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWcryr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWxcu6", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWsshdr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWrcmdc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWahci", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWrcapu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWnfscu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWadpu320", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWpsdir", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWgrubS", version:"11.10.0,REV=2005.09.14.10.55") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWspnego", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWtnfc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWdcar", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWtsr", version:"11.10.0,REV=2006.10.13.15.49") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWrpcib", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWcstl", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWaudit", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWmdu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWtecla", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWpd", version:"11.10.0,REV=2006.05.09.20.40") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWxcu4", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWsshcu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWpsm-ipp", version:"11.10.0.0,REV=2008.02.29.14.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"BRCMbnx", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWudapltr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWpsu", version:"13.1,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWperl584core", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWpapi", version:"11.10.0,REV=2005.01.08.01.09") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWio-tools", version:"11.10.0,REV=2009.06.25.23.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWpcu", version:"13.1,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWixgbe", version:"11.10.0,REV=2008.08.11.22.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWnge", version:"11.10.0,REV=2005.06.22.03.40") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWnxge", version:"11.10.0,REV=2007.07.08.17.21") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWscsip", version:"11.10.0,REV=2008.08.11.22.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWftpu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWgssc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWdtrp", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWsra", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWaac", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWfss", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWib", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWmptsas", version:"11.10.0,REV=2009.07.13.23.13") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWses", version:"11.10.0,REV=2006.03.15.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWbip", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWpsdpr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWippcore", version:"13.1,REV=2005.01.08.01.09") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWlxr", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWamd8111s", version:"11.10.0,REV=2006.11.06.19.53") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWrge", version:"11.10.0,REV=2006.03.27.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWgss", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWos86r", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWnfscr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWsshdu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWrds", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWipfh", version:"11.10.0,REV=2006.05.09.20.40") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWipoib", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWnv-sata", version:"11.10.1,REV=2008.08.11.22.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWhermon", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWsshu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWintgige", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWofk", version:"11.10.0,REV=2010.07.14.14.54") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWsi3124", version:"11.10.0,REV=2006.03.27.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWosdem", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWgrub", version:"11.10.0,REV=2005.09.03.12.22") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWperl584usr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWnfsskr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWudapltu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWpsm-lpd", version:"11.10.0,REV=2005.01.08.01.09") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWipfu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWibsdpib", version:"11.10.0,REV=2008.02.29.14.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWusb", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWnisu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWipplr", version:"13.1,REV=2005.01.08.01.09") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWrdsv3u", version:"11.10.0,REV=2010.07.14.14.54") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWixgb", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWkvm", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWbtool", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWhxge", version:"11.10.0,REV=2009.06.07.23.01") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWudfr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWgssk", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWatfsu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWudf", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWvolu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"144501-19", obsoleted_by:"", package:"SUNWrmwbu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
