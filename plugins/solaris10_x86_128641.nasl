#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(35415);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/09 21:14:08 $");

  script_cve_id("CVE-2009-0217", "CVE-2009-2625", "CVE-2009-3555", "CVE-2011-3564", "CVE-2011-5035");

  script_name(english:"Solaris 10 (x86) : 128641-30");
  script_summary(english:"Check for patch 128641-30");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 128641-30"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Oracle WebLogic Server component of Oracle Fusion
Middleware (subcomponent: Web Container). Supported versions that are
affected are 9.2.4, 10.0.2, 10.3.5, 10.3.6 and 12.1.1. Easily
exploitable vulnerability allows successful unauthenticated network
attacks via HTTP. Successful attack of this vulnerability can result
in unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of Oracle WebLogic Server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/128641-30"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(264, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWasuee", version:"9.1,REV=2007.09.07.14.07") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWasacee", version:"9.1,REV=2007.09.07.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWascml", version:"9.1,REV=2007.09.07.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWasu", version:"9.1,REV=2007.09.07.13.59") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWasdem", version:"9.1,REV=2007.09.07.14.02") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWasr", version:"9.1,REV=2007.09.07.14.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWashdm", version:"9.1,REV=2007.09.07.14.07") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWaswbcr", version:"9.1,REV=2007.09.07.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWasut", version:"9.1,REV=2007.09.07.14.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWasman", version:"9.1,REV=2007.09.07.14.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWascmnse", version:"9.1,REV=2007.09.07.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWasjdoc", version:"9.1,REV=2007.09.07.14.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWaslb", version:"9.1,REV=2007.09.07.14.04") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWascmn", version:"9.1,REV=2007.09.07.14.02") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWasJdbcDrivers", version:"9.1,REV=2007.09.07.14.07") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"128641-30", obsoleted_by:"", package:"SUNWasac", version:"9.1,REV=2007.09.07.13.59") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
