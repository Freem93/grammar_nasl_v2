#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update seamonkey-4596.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27581);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2006-2894", "CVE-2006-4965", "CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-3844", "CVE-2007-3845", "CVE-2007-4841", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");

  script_name(english:"openSUSE 10 Security Update : seamonkey (seamonkey-4596)");
  script_summary(english:"Check for the seamonkey-4596 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes several security issues in Mozilla SeaMonkey 1.0.9.

Following security problems were fixed :

  - MFSA 2007-26 / CVE-2007-3844: Privilege escalation
    through chrome-loaded about:blank windows

    Mozilla researcher moz_bug_r_a4 reported that a flaw was
    introduced by the fix for MFSA 2007-20 that could enable
    privilege escalation attacks against addons that create
    'about:blank' windows and populate them in certain ways
    (including implicit 'about:blank' document creation
    through data: or javascript: URLs in a new window).

  - MFSA 2007-29: Crashes with evidence of memory corruption
    As part of the Firefox 2.0.0.8 update releases Mozilla
    developers fixed many bugs to improve the stability of
    the product. Some of these crashes showed evidence of
    memory corruption under certain circumstances and we
    presume that with enough effort at least some of these
    could be exploited to run arbitrary code.

  - CVE-2007-5339 Browser crashes

  - CVE-2007-5340 JavaScript engine crashes

  - MFSA 2007-30 / CVE-2007-1095: onUnload Tailgating

    Michal Zalewski demonstrated that onUnload event
    handlers had access to the address of the new page about
    to be loaded, even if the navigation was triggered from
    outside the page content such as by using a bookmark,
    pressing the back button, or typing an address into the
    location bar. If the bookmark contained sensitive
    information in the URL the attacking page might be able
    to take advantage of it. An attacking page would also be
    able to redirect the user, perhaps to a phishing page
    that looked like the site the user thought they were
    about to visit.

  - MFSA 2007-31 / CVE-2007-2292: Digest authentication
    request splitting

    Security researcher Stefano Di Paola reported that
    Firefox did not properly validate the user ID when
    making an HTTP request using Digest Authentication to
    log into a website. A malicious page could abuse this to
    inject arbitrary HTTP headers by including a newline
    character in the user ID followed by the injected header
    data. If the user were connecting through a proxy the
    attacker could inject headers that a proxy would
    interpret as two separate requests for different hosts.

  - MFSA 2007-32 / CVE-2007-3511 / CVE-2006-2894: File input
    focus stealing vulnerability

    A user on the Sla.ckers.org forums named hong reported
    that a file upload control could be filled
    programmatically by switching page focus to the label
    before a file upload form control for selected keyboard
    events. An attacker could use this trick to steal files
    from the users' computer if the attacker knew the full
    pathnames to the desired fileis and could create a
    pretext that would convince the user to type long enough
    to produce all the necessary characters.

  - MFSA 2007-33 / CVE-2007-5334: XUL pages can hide the
    window titlebar

    Mozilla developer Eli Friedman discovered that web pages
    written in the XUL markup language (rather than the
    usual HTML) can hide their window's titlebar. It may
    have been possible to abuse this ability to create more
    convincing spoof and phishing pages.

  - MFSA 2007-34 / CVE-2007-5337: Possible file stealing
    through sftp protocol

    On Linux machines with gnome-vfs support the smb: and
    sftp: URI schemes are available in Firefox. Georgi
    Guninski showed that if an attacker can store the attack
    page in a mutually accessible location on the target
    server (/tmp perhaps) and lure the victim into loading
    it, the attacker could potentially read any file owned
    by the victim from known locations on that server.

  - MFSA 2007-35 / CVE-2007-5338: XPCNativeWraper pollution
    using Script object

    Mozilla security researcher moz_bug_r_a4 reported that
    it was possible to use the Script object to modify
    XPCNativeWrappers in such a way that subsequent access
    by the browser chrome--such as by right-clicking to open
    a context menu--can cause attacker-supplied JavaScript
    to run with the same privileges as the user. This is
    similar to MFSA 2007-25 fixed in Firefox 2.0.0.5

Only Windows is affected by :

  - MFSA 2007-27 / CVE-2007-3845: Unescaped URIs passed to
    external programs

    This problem affects Windows only due to their handling
    of URI launchers. 

  - MFSA 2007-28 / CVE-2006-4965: Code execution via
    QuickTime Media-link files

    Linux does not have .lnk files, nor Quicktime. Not
    affected.

  - MFSA 2007-36 / CVE-2007-4841 URIs with invalid
    %-encoding mishandled by Windows

    This problem does not affected Linux."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 94, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-spellchecker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/26");
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

if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-1.0.9-1.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-calendar-1.0.9-1.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-dom-inspector-1.0.9-1.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-irc-1.0.9-1.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-mail-1.0.9-1.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-spellchecker-1.0.9-1.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-venkman-1.0.9-1.5") ) flag++;

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
