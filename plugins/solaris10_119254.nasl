#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(22244);
  script_version("$Revision: 1.95 $");
  script_cvs_date("$Date: 2016/04/05 21:24:24 $");

  script_cve_id("CVE-2006-4439", "CVE-2011-0412");

  script_name(english:"Solaris 10 (sparc) : 119254-93");
  script_summary(english:"Check for patch 119254-93");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119254-93"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10: Install and Patch Utilities Patch.
Date this patch was last updated by Sun : Mar/29/16"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119254-93"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/21");
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

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119254-93", obsoleted_by:"", package:"SUNWinstall-patch-utils-root", version:"11.10,REV=2005.01.09.23.05") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119254-93", obsoleted_by:"", package:"SUNWpkgcmdsr", version:"11.11,REV=2005.01.09.23.05") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119254-93", obsoleted_by:"", package:"SUNWpkgcmdsu", version:"11.11,REV=2005.01.09.23.05") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119254-93", obsoleted_by:"", package:"SUNWswmt", version:"11.10,REV=2005.01.10.17.19") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:solaris_get_report());
  else security_note(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
