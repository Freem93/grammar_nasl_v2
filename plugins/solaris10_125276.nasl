#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(26986);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/08/30 00:06:18 $");

  script_cve_id("CVE-2009-0609");

  script_name(english:"Solaris 10 (sparc) : 125276-10");
  script_summary(english:"Check for patch 125276-10");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 125276-10"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Directory Server Enterprise Edition 6.3.1.1.2 : SunOS 5.10 Sparc N.
Date this patch was last updated by Sun : Jul/15/13"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/125276-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-directory-config", version:"6.0,REV=2007.01.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-directory-ha", version:"6.0,REV=2007.01.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-directory", version:"6.0,REV=2007.01.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-directory-dev", version:"6.0,REV=2007.01.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-console-gui", version:"6.0,REV=2007.01.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-directory-man", version:"6.0,REV=2006.11.06.18.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-proxy", version:"6.0,REV=2007.01.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-directory-client", version:"6.0,REV=2007.01.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-shared", version:"6.0,REV=2007.01.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-console-common", version:"6.0,REV=2007.01.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-proxy-client", version:"6.0,REV=2007.01.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-proxy-config", version:"6.0,REV=2007.01.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-console-gui-help", version:"6.0,REV=2007.01.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-console-agent", version:"6.0,REV=2007.01.25") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-proxy-man", version:"6.0,REV=2006.11.06.18.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125276-10", obsoleted_by:"", package:"SUNWldap-console-cli", version:"6.0,REV=2007.01.25") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
