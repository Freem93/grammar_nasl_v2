#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(22508);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2014/08/30 00:39:38 $");

  script_cve_id("CVE-2007-2882", "CVE-2007-6180");

  script_name(english:"Solaris 8 (x86) : 116960-21");
  script_summary(english:"Check for patch 116960-21");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 116960-21"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.8_x86: nfs and rpcmod patch.
Date this patch was last updated by Sun : Dec/04/07"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/116960-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:C/A:C");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/05");
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

if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"116960-21", obsoleted_by:"127722-02 ", package:"SUNWhea", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;
if (solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"116960-21", obsoleted_by:"127722-02 ", package:"SUNWcsr", version:"11.8.0,REV=2000.01.08.18.17") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
