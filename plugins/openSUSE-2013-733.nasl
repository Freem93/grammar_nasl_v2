#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-733.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75156);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/04 14:10:52 $");

  script_cve_id("CVE-2012-4540");

  script_name(english:"openSUSE Security Update : icedtea-web (openSUSE-SU-2013:1509-1)");
  script_summary(english:"Check for the openSUSE-2013-733 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This icedtea-web update fixes several security issues.

Changes in icedtea-web :

  - update to 1.4.1 (bnc#840572)

  - Improved and cleaned Temporary internet files panel

  - NetX

  - PR1465 - java.io.FileNotFoundException while trying to
    download a JAR file

  - PR1473 - javaws should not depend on name of local file

  - Plugin

  - PR854: Resizing an applet several times causes 100% CPU
    load

  - Security Updates

  - CVE-2013-4349, RH869040: Heap-based buffer overflow
    after triggering event attached to applet CVE-2012-4540
    nit fixed in icedtea-web 1.4

  - Misc 

  - reproducers tests are enabled in dist-tarball

  - application context support for OpenJDK build 25 and
    higher

  - small patches into rhino support and

  - PR1533: Inherit jnlp.packEnabled and jnlp.versionEnabled
    like other properties

  - need jpackage-utils on older distros

  - run more tests in %check

  - drop icedtea-web-AppContext.patch, already upstream

  - add javapackages-tools to build requires"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-09/msg00071.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840572"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icedtea-web packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"icedtea-web-1.4.1-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icedtea-web-debuginfo-1.4.1-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icedtea-web-debugsource-1.4.1-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icedtea-web-javadoc-1.4.1-1.25.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icedtea-web-1.4.1-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icedtea-web-debuginfo-1.4.1-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icedtea-web-debugsource-1.4.1-4.22.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icedtea-web-javadoc-1.4.1-4.22.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-web / icedtea-web-debuginfo / icedtea-web-debugsource / etc");
}
