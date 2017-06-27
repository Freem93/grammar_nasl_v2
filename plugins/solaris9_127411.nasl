#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(71741);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2010-4438");

  script_name(english:"Solaris 9 (sparc) : 127411-16");
  script_summary(english:"Check for patch 127411-16");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 127411-16"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Message Queue 4.1 Update 4 Patch 6 SunOS 5.9 5.10 Core product.
Date this patch was last updated by Sun : Mar/12/12"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/127411-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127411-16", obsoleted_by:"", package:"SUNWiqfs", version:"4.1,REV=2007.07.26.10.59") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127411-16", obsoleted_by:"", package:"SUNWiqum", version:"4.1,REV=2007.07.26.10.59") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127411-16", obsoleted_by:"", package:"SUNWiqr", version:"4.1,REV=2007.07.26.10.58") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127411-16", obsoleted_by:"", package:"SUNWiquc", version:"4.1,REV=2007.07.26.10.59") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127411-16", obsoleted_by:"", package:"SUNWiqdoc", version:"4.1,REV=2007.07.26.10.58") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127411-16", obsoleted_by:"", package:"SUNWiqu", version:"4.1,REV=2007.07.26.10.58") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127411-16", obsoleted_by:"", package:"SUNWiqjx", version:"4.1,REV=2007.07.26.10.59") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
