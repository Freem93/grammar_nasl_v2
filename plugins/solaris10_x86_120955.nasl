#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(38126);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/09 21:14:08 $");

  script_cve_id("CVE-2006-0531", "CVE-2008-2945", "CVE-2008-3529", "CVE-2008-4225", "CVE-2008-4226", "CVE-2009-0170", "CVE-2009-0348", "CVE-2009-2268", "CVE-2009-2712", "CVE-2009-2713", "CVE-2010-4444");

  script_name(english:"Solaris 10 (x86) : 120955-12");
  script_summary(english:"Check for patch 120955-12");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 120955-12"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"AM 7.0_x86: Sun Java System Access Manager 2005Q4.
Date this patch was last updated by Sun : Nov/03/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/120955-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 119, 189, 200, 255, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120955-12", obsoleted_by:"", package:"SUNWamclnt", version:"7.0,REV=05.08.10.09.18") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120955-12", obsoleted_by:"", package:"SUNWamsam", version:"7.0,REV=05.08.10.09.18") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120955-12", obsoleted_by:"", package:"SUNWamconsdk", version:"7.0,REV=05.08.10.09.18") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120955-12", obsoleted_by:"", package:"SUNWamsfodb", version:"7.0,REV=05.08.10.09.18") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120955-12", obsoleted_by:"", package:"SUNWamfcd", version:"7.0,REV=05.08.10.09.18") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120955-12", obsoleted_by:"", package:"SUNWamsvc", version:"7.0,REV=05.08.10.09.17") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120955-12", obsoleted_by:"", package:"SUNWampwd", version:"7.0,REV=05.08.10.09.18") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120955-12", obsoleted_by:"", package:"SUNWamsdkconfig", version:"7.0,REV=05.08.10.09.18") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120955-12", obsoleted_by:"", package:"SUNWamutl", version:"7.0,REV=05.08.10.09.07") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120955-12", obsoleted_by:"", package:"SUNWamsdk", version:"7.0,REV=05.08.10.09.18") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120955-12", obsoleted_by:"", package:"SUNWamcon", version:"7.0,REV=05.08.10.09.18") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120955-12", obsoleted_by:"", package:"SUNWamsvcconfig", version:"7.0,REV=05.08.10.09.18") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"120955-12", obsoleted_by:"", package:"SUNWamdistauth", version:"7.0,REV=05.08.10.09.18") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
