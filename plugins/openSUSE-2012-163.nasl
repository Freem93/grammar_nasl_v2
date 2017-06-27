#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-163.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74568);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-3377");

  script_name(english:"openSUSE Security Update : icedtea-web (openSUSE-SU-2012:0371-1)");
  script_summary(english:"Check for the openSUSE-2012-163 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to 1.2

  - New features :

  - Signed JNLP support

  - Support for client authentication certificates

  - Cache size enforcement now supported via itweb-settings

  - Applet parameter passing through JNLP files now
    supported

  - Better icons for access warning dialog

  - Security Dialog UI revamped to make it look less
    threatening when appropriate

  - Fixes (plugin, webstart, common)

  - PR618: Can't install OpenDJ, JavaWebStart fails with
    Input stream is null error

  - PR765: JNLP file with all resource jars marked as 'lazy'
    fails to validate signature and stops the launch of
    application

  - PR788: Elluminate Live! is not working

  - PR804: javaws launcher incorrectly handles file names
    with spaces

  - PR820, bnc#746895: IcedTea-Web 1.1.3 crashing Firefox
    when loading Citrix XenApp

  - PR838: IcedTea plugin crashes with chrome browser when
    JavaScript is executed

  - PR852: Classloader not being flushed after last applet
    from a site is closed

  - RH586194: Unable to connect to connect with Juniper VPN
    client

  - PR771: IcedTea-Web certificate verification code does
    not use the right API

  - PR742: IcedTea-Web checks certs only upto 1 level deep
    before declaring them untrusted.

  - PR789: typo in jrunscript.sh

  - PR808: javaws is unable to start, when missing jars are
    enumerated before main jar

  - RH738814: Access denied at ssl handshake

  - Support for authenticating using client certificates

  - fix bnc#737105/FATE#313084: add Supplements:
    packageand(broswer(npapi):java-openjdk) ensures the web
    plugin is pulled in when openjdk and capable browser is
    installed

  - enable make check in respective section

  - update to 1.1.4 (fixes bnc#729870)

  - RH742515, CVE-2011-3377: IcedTea-Web: second-level
    domain subdomains and suffix domain SOP bypass

  - PR778: Jar download and server certificate verification
    deadlock"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-03/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=729870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=737105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746895"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icedtea-web packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/08");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"icedtea-web-1.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"icedtea-web-debuginfo-1.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"icedtea-web-debugsource-1.2-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"icedtea-web-javadoc-1.2-3.1") ) flag++;

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
