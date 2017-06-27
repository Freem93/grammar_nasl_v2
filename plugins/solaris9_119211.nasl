#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(19842);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/03/23 13:55:26 $");

  script_cve_id("CVE-2005-2096", "CVE-2006-4339", "CVE-2006-5201", "CVE-2006-7140");

  script_name(english:"Solaris 9 (sparc) : 119211-33");
  script_summary(english:"Check for patch 119211-33");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119211-33"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NSS_NSPR_JSS 3.21: NSPR 4.11 / NSS 3.21 / JSS 4.3.2.
Date this patch was last updated by Sun : Mar/22/16"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119211-33"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"119211-33", obsoleted_by:"", package:"SUNWprd", version:"4.1.6,REV=2003.09.08.10.19") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"119211-33", obsoleted_by:"", package:"SUNWjss", version:"3.1.2.3,REV=2003.03.08.12.17") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"119211-33", obsoleted_by:"", package:"SUNWtlsux", version:"3.3.10,REV=2004.03.25.01.10") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"119211-33", obsoleted_by:"", package:"SUNWtls", version:"3.3.2,REV=2002.09.18.12.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"119211-33", obsoleted_by:"", package:"SUNWprx", version:"4.1.2,REV=2002.09.03.00.17") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"119211-33", obsoleted_by:"", package:"SUNWpr", version:"4.1.2,REV=2002.09.03.00.17") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"119211-33", obsoleted_by:"", package:"SUNWtlsu", version:"3.3.7,REV=2003.12.01.12.23") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"119211-33", obsoleted_by:"", package:"SUNWtlsd", version:"3.3.6,REV=2003.09.08.10.30") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"119211-33", obsoleted_by:"", package:"SUNWtlsx", version:"3.3.2,REV=2002.09.18.12.49") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"119211-33", obsoleted_by:"", package:"SUNWjssx", version:"3.1.2.3,REV=2003.03.08.12.22") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
