#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(19370);
  script_version("$Revision: 1.34 $");
  script_cvs_date("$Date: 2014/08/30 00:11:54 $");

  script_cve_id("CVE-2004-0790", "CVE-2004-0791", "CVE-2005-3250", "CVE-2005-4701", "CVE-2008-1095");

  script_name(english:"Solaris 10 (x86) : 118844-20");
  script_summary(english:"Check for patch 118844-20");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 118844-20"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10_x86: kernel Patch.
Date this patch was last updated by Sun : Oct/28/05"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/118844-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWpsdcr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWcpcu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWdtrp", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNW1394", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWib", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWscpu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWftdur", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWos86r", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWpcmci", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWrcapu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWpsdir", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWtnfc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWpsh", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWmdu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWipfu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWusb", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWkey", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118844-20", obsoleted_by:"118855-36 ", package:"SUNWrmwbu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
