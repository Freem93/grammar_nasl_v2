#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(22989);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_cve_id("CVE-2007-3700", "CVE-2009-0170", "CVE-2009-0348", "CVE-2009-2268", "CVE-2009-2712");

  script_name(english:"Solaris 10 (x86) : 119465-17");
  script_summary(english:"Check for patch 119465-17");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119465-17"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Java(TM) System Access Manager 6 2005Q1.
Date this patch was last updated by Sun : Jun/29/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119465-17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cwe_id(79, 200, 255, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119465-17", obsoleted_by:"", package:"SUNWamfcd", version:"6.2,REV=04.04.23.20.25") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119465-17", obsoleted_by:"", package:"SUNWamclnt", version:"6.3,REV=04.12.14.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119465-17", obsoleted_by:"", package:"SUNWamsam", version:"6.2,REV=04.04.23.20.25") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119465-17", obsoleted_by:"", package:"SUNWamsvc", version:"6.2,REV=04.04.23.20.25") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119465-17", obsoleted_by:"", package:"SUNWampwd", version:"6.2,REV=04.04.23.20.25") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119465-17", obsoleted_by:"", package:"SUNWamsdkconfig", version:"6.2,REV=04.04.23.20.25") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119465-17", obsoleted_by:"", package:"SUNWamsdk", version:"6.2,REV=04.04.23.20.25") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119465-17", obsoleted_by:"", package:"SUNWamconsdk", version:"6.2,REV=04.04.23.20.25") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119465-17", obsoleted_by:"", package:"SUNWamcon", version:"6.2,REV=04.04.23.20.25") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119465-17", obsoleted_by:"", package:"SUNWamsvcconfig", version:"6.2,REV=04.04.23.20.25") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119465-17", obsoleted_by:"", package:"SUNWamsfodb", version:"6.3,REV=04.12.14.01.46") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
