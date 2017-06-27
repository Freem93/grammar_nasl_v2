#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update horde-1868.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27265);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:11:35 $");

  script_cve_id("CVE-2006-3548", "CVE-2006-3549");

  script_name(english:"openSUSE 10 Security Update : horde (horde-1868)");
  script_summary(english:"Check for the horde-1868 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following two security issues in the Horde
Application Framework :

  - CVE-2006-3548: Multiple cross-site scripting (XSS)
    vulnerabilities allow remote attackers to inject
    arbitrary web script or HTML via a (1) JavaScript URI or
    an external (2) http, (3) https, or (4) ftp URI in the
    url parameter in services/go.php (aka the dereferrer),
    (5) a JavaScript URI in the module parameter in
    services/help (aka the help viewer), and (6) the name
    parameter in services/problem.php (aka the problem
    reporting screen).

  - CVE-2006-3549: services/go.php does not properly
    restrict its image proxy capability, which allows remote
    attackers to perform 'Web tunneling' attacks and use the
    server as a proxy via (1) http, (2) https, and (3) ftp
    URL in the url parameter, which is requested from the
    server."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected horde package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:horde");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"horde-3.0.9-19.4") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "horde");
}
