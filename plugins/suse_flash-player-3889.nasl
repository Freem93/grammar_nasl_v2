#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update flash-player-3889.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27221);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:32:45 $");

  script_cve_id("CVE-2007-2022", "CVE-2007-3456", "CVE-2007-3457");

  script_name(english:"openSUSE 10 Security Update : flash-player (flash-player-3889)");
  script_summary(english:"Check for the flash-player-3889 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Adobe Flash Player was updated to version 7.0.70.0 on SUSE Linux
10.0 and to version 9.0.48.0 on SUSE Linux 10.1 and openSUSE 10.2 to
fix several security problems :

CVE-2007-3456: An input validation error has been identified in Flash
Player 9.0.45.0 and earlier versions that could lead to the potential
execution of arbitrary code. This vulnerability could be accessed
through content delivered from a remote location via the user's web
browser, email client, or other applications that include or reference
the Flash Player.

CVE-2007-3457: An issue with insufficient validation of the HTTP
Referer has been identified in Flash Player 8.0.34.0 and earlier. This
issue does not affect Flash Player 9. This issue could potentially aid
an attacker in executing a cross-site request forgery attack.

CVE-2007-2022: The Linux and Solaris updates for Flash Player 7
(7.0.70.0) address the issues with Flash Player and the Opera and
Konqueror browsers described in Security Advisory APSA07-03. These
issues do not impact Flash Player 9 on Linux or Solaris.

The affected webbrowsers Opera and konqueror have already been fixed
independendly."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-player package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 200, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"flash-player-9.0.48.0-1.2") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"flash-player-9.0.48.0-1.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-player");
}
