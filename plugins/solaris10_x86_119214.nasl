#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(20055);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/03/23 13:55:26 $");

  script_cve_id("CVE-2006-4339", "CVE-2006-4842", "CVE-2006-5201", "CVE-2006-7140");

  script_name(english:"Solaris 10 (x86) : 119214-33");
  script_summary(english:"Check for patch 119214-33");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119214-33"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"NSS_NSPR_JSS 3.21_x86: NSPR 4.11 / NSS 3.21 / JSS 4.3.2.
Date this patch was last updated by Sun : Mar/22/16"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119214-33"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/19");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119214-33", obsoleted_by:"", package:"SUNWprd", version:"4.5.1,REV=2004.11.05.03.44") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119214-33", obsoleted_by:"", package:"SUNWjss", version:"4.0,REV=2004.11.05.03.05") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119214-33", obsoleted_by:"", package:"SUNWtls", version:"3.9.5,REV=2005.01.14.19.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119214-33", obsoleted_by:"", package:"SUNWpr", version:"4.5.1,REV=2004.11.05.03.44") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119214-33", obsoleted_by:"", package:"SUNWtlsu", version:"3.9.5,REV=2005.01.14.19.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119214-33", obsoleted_by:"", package:"SUNWtlsd", version:"3.9.5,REV=2005.01.14.19.03") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
