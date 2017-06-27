#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(13520);
  script_version("$Revision: 1.54 $");
  script_cvs_date("$Date: 2016/12/09 21:14:09 $");

  script_cve_id("CVE-2004-0523", "CVE-2004-0653", "CVE-2005-1689", "CVE-2006-6144", "CVE-2008-5690", "CVE-2009-0360", "CVE-2009-0361", "CVE-2009-1933", "CVE-2012-1683");

  script_name(english:"Solaris 9 (sparc) : 112908-38");
  script_summary(english:"Check for patch 112908-38");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 112908-38"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.9: krb5, gss patch.
Date this patch was last updated by Sun : Sep/14/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/112908-38"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 255, 264, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
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

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112908-38", obsoleted_by:"", package:"SUNWcstlx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112908-38", obsoleted_by:"", package:"SUNWhea", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112908-38", obsoleted_by:"", package:"SUNWgssx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112908-38", obsoleted_by:"", package:"SUNWcstl", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112908-38", obsoleted_by:"", package:"SUNWcar", version:"11.9.0,REV=2002.04.09.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112908-38", obsoleted_by:"", package:"SUNWkrbr", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112908-38", obsoleted_by:"", package:"SUNWcarx", version:"11.9.0,REV=2002.04.09.12.25") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112908-38", obsoleted_by:"", package:"SUNWkrbux", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112908-38", obsoleted_by:"", package:"SUNWkrbu", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112908-38", obsoleted_by:"", package:"SUNWgss", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112908-38", obsoleted_by:"", package:"SUNWgsskx", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112908-38", obsoleted_by:"", package:"SUNWgssk", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"112908-38", obsoleted_by:"", package:"SUNWcsr", version:"11.9.0,REV=2002.04.06.15.27") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
