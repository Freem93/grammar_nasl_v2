#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(13593);
  script_version("$Revision: 1.36 $");
  script_cvs_date("$Date: 2016/12/09 21:14:09 $");

  script_cve_id("CVE-2003-0020", "CVE-2003-0542", "CVE-2003-0987", "CVE-2003-0993", "CVE-2004-0174", "CVE-2004-0492", "CVE-2007-1349");

  script_name(english:"Solaris 9 (x86) : 114145-12");
  script_summary(english:"Check for patch 114145-12");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 114145-12"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9_x86: Apache Security Patch.
Date this patch was last updated by Sun : Mar/05/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.oracle.com/sunalerts/1021709.1.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114145-12", obsoleted_by:"", package:"SUNWapchu", version:"11.9.0,REV=2002.08.06.16.05") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114145-12", obsoleted_by:"", package:"SUNWapchd", version:"11.9.0,REV=2002.08.06.16.05") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114145-12", obsoleted_by:"", package:"SUNWapchS", version:"11.9.0,REV=2002.08.06.16.05") < 0) flag++;
if (solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114145-12", obsoleted_by:"", package:"SUNWapchr", version:"11.9.0,REV=2002.08.06.16.05") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
