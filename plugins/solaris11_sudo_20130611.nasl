#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80779);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2013-1775", "CVE-2013-1776");

  script_name(english:"Oracle Solaris Third-Party Patch Update : sudo (multiple_permissions_privileges_and_access)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - sudo 1.6.0 through 1.7.10p6 and sudo 1.8.0 through
    1.8.6p6 allows local users or physically proximate
    attackers to bypass intended time restrictions and
    retain privileges without re-authenticating by setting
    the system clock and sudo user timestamp to the epoch.
    (CVE-2013-1775)

  - sudo 1.3.5 through 1.7.10 and 1.8.0 through 1.8.5, when
    the tty_tickets option is enabled, does not properly
    validate the controlling terminal device, which allows
    local users with sudo permissions to hijack the
    authorization of another terminal via vectors related to
    connecting to the standard input, output, and error file
    descriptors of another terminal. NOTE: this is one of
    three closely-related vulnerabilities that were
    originally assigned CVE-2013-1776, but they have been
    SPLIT because of different affected versions.
    (CVE-2013-1776)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_permissions_privileges_and_access
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69db58b0"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.7.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Sudo Password Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:sudo");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^sudo$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.7.0.5.0", sru:"SRU 11.1.7.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : sudo\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "sudo");
