#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(39005);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/30 00:50:08 $");

  script_cve_id("CVE-2009-0217");

  script_name(english:"Solaris 9 (x86) : 141710-03");
  script_summary(english:"Check for patch 141710-03");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 141710-03"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun GlassFish Enterprise Server v2.1.1 Security Patch01, _x86: SVR.
Date this patch was last updated by Sun : Jan/08/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/141710-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWasuee", version:"9.1,REV=2007.09.07.14.07") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWasacee", version:"9.1,REV=2007.09.07.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWascml", version:"9.1,REV=2007.09.07.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWasu", version:"9.1,REV=2007.09.07.13.59") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWasdem", version:"9.1,REV=2007.09.07.14.02") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWasr", version:"9.1,REV=2007.09.07.14.03") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWashdm", version:"9.1,REV=2007.09.07.14.07") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWaswbcr", version:"9.1,REV=2007.09.07.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWasut", version:"9.1,REV=2007.09.07.14.03") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWasman", version:"9.1,REV=2007.09.07.14.03") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWascmnse", version:"9.1,REV=2007.09.07.14.08") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWasjdoc", version:"9.1,REV=2007.09.07.14.03") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWaslb", version:"9.1,REV=2007.09.07.14.04") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWascmn", version:"9.1,REV=2007.09.07.14.02") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWasJdbcDrivers", version:"9.1,REV=2007.09.07.14.07") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"141710-03", obsoleted_by:"", package:"SUNWasac", version:"9.1,REV=2007.09.07.13.59") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
