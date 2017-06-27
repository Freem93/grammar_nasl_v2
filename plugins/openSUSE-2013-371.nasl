#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-371.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74979);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:13 $");

  script_cve_id("CVE-2013-1926", "CVE-2013-1927");

  script_name(english:"openSUSE Security Update : icedtea-web (openSUSE-SU-2013:0715-1)");
  script_summary(english:"Check for the openSUSE-2013-371 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to 1.3.2 (bnc#815596) 

  - Security Updates

  - CVE-2013-1927, RH884705: fixed gifar vulnerability

  - CVE-2013-1926, RH916774: Class-loader incorrectly shared
    for applets with same relative-path.

  - Common

  - Added new option in itw-settings which allows users to
    set JVM arguments when plugin is initialized.

  - NetX

  - PR580: http://www.horaoficial.cl/ loads improperly

  - Plugin

  - PR1260: IcedTea-Web should not rely on GTK obsoletes
    icedtea-web-remove-gtk-dep.patch

  - PR1157: Applets can hang browser after fatal exception

  - Add icedtea-web-remove-gtk-dep.patch, build icedtea-web
    without GTK. Plugin now works in both gtk2 and gtk3
    based browsers.

  - limit the provides/obsoletes to architectures, where
    -plugin package existed and don't pollute shiny new arm
    with an old garbage

  - handle the package renaming on arm properly"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-04/msg00106.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.horaoficial.cl/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815596"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/17");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"icedtea-web-1.3.2-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icedtea-web-debuginfo-1.3.2-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icedtea-web-debugsource-1.3.2-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icedtea-web-javadoc-1.3.2-1.13.1") ) flag++;

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
