#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(22967);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/01/27 16:45:02 $");

  script_cve_id("CVE-2006-5857", "CVE-2007-0045", "CVE-2007-0046");

  script_name(english:"Solaris 10 (sparc) : 121104-11");
  script_summary(english:"Check for patch 121104-11");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 121104-11"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10: Adobe Acrobat Reader patch.
Date this patch was last updated by Sun : Nov/27/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/121104-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/27");
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

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"121104-11", obsoleted_by:"", package:"SUNWacroread", version:"1.0,REV=10.0.3.2004.12.21.12.29") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");