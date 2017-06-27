#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(40587);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/30 00:11:56 $");

  script_cve_id("CVE-2009-3923");

  script_name(english:"Solaris 10 (x86) : 141482-03");
  script_summary(english:"Check for patch 141482-03");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 141482-03"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Virtual Desktop Infrastructure Software version 3.0 Patch Upda.
Date this patch was last updated by Sun : Oct/30/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/141482-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/13");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141482-03", obsoleted_by:"", package:"SUNWvda-admin-libs-fr", version:"3.0_71,REV=2009.03.11.11.27") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141482-03", obsoleted_by:"", package:"SUNWvda-admin-libs-ja", version:"3.0_71,REV=2009.03.11.11.27") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141482-03", obsoleted_by:"", package:"SUNWvda-admin-libs-zh", version:"3.0_71,REV=2009.03.11.11.27") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141482-03", obsoleted_by:"", package:"SUNWvda-kiosk", version:"3.0_71,REV=2009.03.11.11.27") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141482-03", obsoleted_by:"", package:"SUNWvda-migrate", version:"3.0_71,REV=2009.03.11.11.27") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141482-03", obsoleted_by:"", package:"SUNWvda-admin-libs-sv", version:"3.0_71,REV=2009.03.11.11.27") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141482-03", obsoleted_by:"", package:"SUNWvda-admin", version:"3.0_71,REV=2009.03.11.11.27") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141482-03", obsoleted_by:"", package:"SUNWrdpb", version:"1.0_9") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141482-03", obsoleted_by:"", package:"SUNWvda-client", version:"3.0_71,REV=2009.03.11.11.27") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141482-03", obsoleted_by:"", package:"SUNWvda-service", version:"3.0_71,REV=2009.03.11.11.27") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
