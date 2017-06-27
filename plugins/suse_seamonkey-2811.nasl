#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update seamonkey-2811.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27440);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0995", "CVE-2007-0996");

  script_name(english:"openSUSE 10 Security Update : seamonkey (seamonkey-2811)");
  script_summary(english:"Check for the seamonkey-2811 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update brings Mozilla SeaMonkey to version 1.0.8.

Please also see
http://www.mozilla.org/projects/security/known-vulnerabilities.html
for more details.

It includes fixes to the following security problems :

  - MFSA 2007-01: As part of the Firefox 2.0.0.2 and
    1.5.0.10 update releases several bugs were fixed to
    improve the stability of the browser. Some of these were
    crashes that showed evidence of memory corruption and we
    presume that with enough effort at least some of these
    could be exploited to run arbitrary code. These fixes
    affected the layout engine (CVE-2007-0775), SVG renderer
    (CVE-2007-0776) and JavaScript engine (CVE-2007-0777).

  - MFSA 2007-02: Various enhancements were done to make XSS
    exploits against websites less effective. These included
    fixes for invalid trailing characters (CVE-2007-0995),
    child frame character set inheritance (CVE-2007-0996),
    password form injection (CVE-2006-6077), and the Adobe
    Reader universal XSS problem.

  - MFSA 2007-03/CVE-2007-0778: AAd reported a potential
    disk cache collision that could be exploited by remote
    attackers to steal confidential data or execute code.

  - MFSA 2007-04/CVE-2007-0779: David Eckel reported that
    browser UI elements--such as the host name and security
    indicators--could be spoofed by using a large, mostly
    transparent, custom cursor and adjusting the CSS3
    hotspot property so that the visible part of the cursor
    floated outside the browser content area.

  - MFSA 2007-05: Manually opening blocked popups could be
    exploited by remote attackers to allow XSS attacks
    (CVE-2007-0780) or to execute code in local files
    (CVE-2007-0800).

  - MFSA 2007-06: Two buffer overflows were found in the NSS
    handling of Mozilla.

    CVE-2007-0008: SSL clients such as Firefox and
    Thunderbird can suffer a buffer overflow if a malicious
    server presents a certificate with a public key that is
    too small to encrypt the entire 'Master Secret'.
    Exploiting this overflow appears to be unreliable but
    possible if the SSLv2 protocol is enabled.

    CVE-2007-0009: Servers that use NSS for the SSLv2
    protocol can be exploited by a client that presents a
    'Client Master Key' with invalid length values in any of
    several fields that are used without adequate error
    checking. This can lead to a buffer overflow that
    presumably could be exploitable.

  - MFSA 2007-06/CVE-2007-0981: Michal Zalewski demonstrated
    that setting location.hostname to a value with embedded
    null characters can confuse the browsers domain checks.
    Setting the value triggers a load, but the networking
    software reads the hostname only up to the null
    character while other checks for 'parent domain' start
    at the right and so can have a completely different idea
    of what the current host is."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-spellchecker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/13");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-1.0.8-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-calendar-1.0.8-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-dom-inspector-1.0.8-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-irc-1.0.8-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-mail-1.0.8-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-spellchecker-1.0.8-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-venkman-1.0.8-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey");
}
