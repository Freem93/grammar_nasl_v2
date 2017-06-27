#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-439.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75010);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/28 13:51:53 $");

  script_cve_id("CVE-2012-3422", "CVE-2012-3423", "CVE-2013-1926", "CVE-2013-1927");
  script_osvdb_id(84362, 84363);

  script_name(english:"openSUSE Security Update : icedtea-web (openSUSE-SU-2013:0893-1)");
  script_summary(english:"Check for the openSUSE-2013-439 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in icedtea-web with update to 1.4 (bnc#818768) :

  - Added cs, de, pl localization

  - Splash screen for javaws and plugin

  - Better error reporting for plugin via
    Error-splash-screen

  - All IcedTea-Web dialogues are centered to middle of
    active screen

  - Download indicator made compact for more then one jar

  - User can select its own JVM via itw-settings and
    deploy.properties.

  - Added extended applets security settings and dialogue

  - Security updates

  - CVE-2013-1926, RH916774: Class-loader incorrectly shared
    for applets with same relative-path.

  - CVE-2013-1927, RH884705: fixed gifar vulnerabilit

  - CVE-2012-3422, RH840592: Potential read from an
    uninitialized memory location

  - CVE-2012-3423, RH841345: Incorrect handling of not
    0-terminated strings

  - NetX

  - PR1027: DownloadService is not supported by IcedTea-Web

  - PR725: JNLP applications will prompt for creating
    desktop shortcuts every time they are run

  - PR1292: Javaws does not resolve versioned jar names with
    periods correctly

  - Plugin

  - PR1106: Buffer overflow in plugin table-

  - PR1166: Embedded JNLP File is not supported in applet
    tag

  - PR1217: Add command line arguments for plugins

  - PR1189: Icedtea-plugin requires code attribute when
    using jnlp_href

  - PR1198: JSObject is not passed to JavaScript correctly

  - PR1260: IcedTea-Web should not rely on GTK

  - PR1157: Applets can hang browser after fatal exception

  - PR580: http://www.horaoficial.cl/ loads improperly

  - Common

  - PR1049: Extension jnlp's signed jar with the content of
    only META-INF/* is considered

  - PR955: regression: SweetHome3D fails to run

  - PR1145: IcedTea-Web can cause ClassCircularityError

  - PR1161: X509VariableTrustManager does not work correctly
    with OpenJDK7

  - PR822: Applets fail to load if jars have different
    signers

  - PR1186:
    System.getProperty('deployment.user.security.trusted.cac
    erts') is null

  - PR909: The Java applet at
    http://de.gosupermodel.com/games/wardrobegame.jsp fails

  - PR1299: WebStart doesn't read socket proxy settings from
    firefox correctly"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://de.gosupermodel.com/games/wardrobegame.jsp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-05/msg00032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.horaoficial.cl/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818768"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icedtea-web packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.2", reference:"icedtea-web-1.4-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icedtea-web-debuginfo-1.4-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icedtea-web-debugsource-1.4-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"icedtea-web-javadoc-1.4-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icedtea-web-1.4-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icedtea-web-debuginfo-1.4-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icedtea-web-debugsource-1.4-4.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"icedtea-web-javadoc-1.4-4.14.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-web / icedtea-web-debuginfo / icedtea-web-debugsource / etc");
}
