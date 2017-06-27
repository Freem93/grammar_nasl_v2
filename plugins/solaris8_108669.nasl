#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(23301);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2014/08/30 00:17:44 $");

  script_cve_id("CVE-2008-5009");

  script_name(english:"Solaris 8 (sparc) : 108669-21");
  script_summary(english:"Check for patch 108669-21");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 108669-21"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Solstice X.25 9.2 patch.
Date this patch was last updated by Sun : Oct/10/08"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/108669-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108669-21", obsoleted_by:"", package:"SUNWx25b", version:"9.2") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108669-21", obsoleted_by:"", package:"SUNWx25a", version:"9.2") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108669-21", obsoleted_by:"", package:"SUNWx25ax", version:"9.2") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"108669-21", obsoleted_by:"", package:"SUNWx25bx", version:"9.2") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
