#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-530.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77618);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/08/24 13:49:14 $");

  script_cve_id("CVE-2014-1553", "CVE-2014-1554", "CVE-2014-1562", "CVE-2014-1563", "CVE-2014-1564", "CVE-2014-1565", "CVE-2014-1567");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-SU-2014:1099-1)");
  script_summary(english:"Check for the openSUSE-2014-530 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to Firefox 32 fixing security issues and
bugs.

Security issues fixed: MFSA 2014-72 / CVE-2014-1567: Security
researcher regenrecht reported, via TippingPoint's Zero Day
Initiative, a use-after-free during text layout when interacting with
the setting of text direction. This results in a use-after-free which
can lead to arbitrary code execution.

MFSA 2014-70 / CVE-2014-1565: Security researcher Holger Fuhrmannek
discovered an out-of-bounds read during the creation of an audio
timeline in Web Audio. This results in a crash and could allow for the
reading of random memory values.

MFSA 2014-69 / CVE-2014-1564: Google security researcher Michal
Zalewski discovered that when a malformated GIF image is rendered in
certain circumstances, memory is not properly initialized before use.
The resulting image then uses this memory during rendering. This could
allow for the a script in web content to access this uninitialized
memory using the <canvas> feature.

MFSA 2014-68 / CVE-2014-1563: Security researcher Abhishek Arya
(Inferno) of the Google Chrome Security Team used the Address
Sanitizer tool to discover a use-after-free during cycle collection.
This was found in interactions with the SVG content through the
document object model (DOM) with animating SVG content. This leads to
a potentially exploitable crash.

MFSA 2014-67: Mozilla developers and community identified and fixed
several memory safety bugs in the browser engine used in Firefox and
other Mozilla-based products. Some of these bugs showed evidence of
memory corruption under certain circumstances, and we presume that
with enough effort at least some of these could be exploited to run
arbitrary code.

Jan de Mooij reported a memory safety problem that affects Firefox ESR
24.7, ESR 31 and Firefox 31. (CVE-2014-1562)

Christian Holler, Jan de Mooij, Karl Tomlinson, Randell Jesup, Gary
Kwong, Jesse Ruderman, and JW Wang reported memory safety problems and
crashes that affect Firefox ESR 31 and Firefox 31. (CVE-2014-1553)

Gary Kwong, Christian Holler, and David Weir reported memory safety
problems and crashes that affect Firefox 31. (CVE-2014-1554)

Mozilla NSS was updated to 3.16.4: Notable Changes :

  - The following 1024-bit root CA certificate was restored
    to allow more time to develop a better transition
    strategy for affected sites. It was removed in NSS
    3.16.3, but discussion in the
    mozilla.dev.security.policy forum led to the decision to
    keep this root included longer in order to give website
    administrators more time to update their web servers.

  - CN = GTE CyberTrust Global Root

  - In NSS 3.16.3, the 1024-bit 'Entrust.net Secure Server
    Certification Authority' root CA certificate was
    removed. In NSS 3.16.4, a 2048-bit intermediate CA
    certificate has been included, without explicit trust.
    The intention is to mitigate the effects of the previous
    removal of the 1024-bit Entrust.net root certificate,
    because many public Internet sites still use the
    'USERTrust Legacy Secure Server CA' intermediate
    certificate that is signed by the 1024-bit Entrust.net
    root certificate. The inclusion of the intermediate
    certificate is a temporary measure to allow those sites
    to function, by allowing them to find a trust path to
    another 2048-bit root CA certificate. The temporarily
    included intermediate certificate expires November 1,
    2015."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-09/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=894201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=894370"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/11");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-31.1.0-1.86.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-branding-upstream-31.1.0-1.86.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-buildsymbols-31.1.0-1.86.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debuginfo-31.1.0-1.86.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debugsource-31.1.0-1.86.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-devel-31.1.0-1.86.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-common-31.1.0-1.86.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-other-31.1.0-1.86.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-debuginfo-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-debuginfo-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-debuginfo-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debuginfo-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debugsource-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-devel-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-debuginfo-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-debuginfo-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-32bit-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.16.4-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-31.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-upstream-31.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-buildsymbols-31.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debuginfo-31.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debugsource-31.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-devel-31.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-common-31.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-other-31.1.0-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-debuginfo-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-debuginfo-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-debuginfo-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debuginfo-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debugsource-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-devel-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-debuginfo-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-debuginfo-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.16.4-35.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.16.4-35.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
