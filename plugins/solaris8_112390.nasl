#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(13388);
  script_version("$Revision: 1.34 $");
  script_cvs_date("$Date: 2014/08/30 00:33:49 $");

  script_cve_id("CVE-2005-1689");

  script_name(english:"Solaris 8 (sparc) : 112390-14");
  script_summary(english:"Check for patch 112390-14");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 112390-14"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.8: Supplemental Encryption Kerbero.
Date this patch was last updated by Sun : Mar/24/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/112390-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"112390-14", obsoleted_by:"", package:"SUNWk5pu", version:"11.8.0,REV=1999.12.07.04.22") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"112390-14", obsoleted_by:"", package:"SUNWk5pkx", version:"11.8.0,REV=1999.12.07.04.22") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"112390-14", obsoleted_by:"", package:"SUNWk5pk", version:"11.8.0,REV=1999.12.07.04.22") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"112390-14", obsoleted_by:"", package:"SUNWk5pux", version:"11.8.0,REV=1999.12.07.04.22") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
