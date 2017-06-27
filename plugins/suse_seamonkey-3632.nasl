#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update seamonkey-3632.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27442);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2007-1362", "CVE-2007-1558", "CVE-2007-1562", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");

  script_name(english:"openSUSE 10 Security Update : seamonkey (seamonkey-3632)");
  script_summary(english:"Check for the seamonkey-3632 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla SeaMonkey to security update version 1.1.2

  - MFSA 2007-17 / CVE-2007-2871 :

    Chris Thomas demonstrated that XUL popups opened by web
    content could be placed outside the boundaries of the
    content area. This could be used to spoof or hide parts
    of the browser chrome such as the location bar.

  - MFSA 2007-16 / CVE-2007-2870 :

    Mozilla contributor moz_bug_r_a4 demonstrated that the
    addEventListener method could be used to inject script
    into another site in violation of the browser's
    same-origin policy. This could be used to access or
    modify private or valuable information from that other
    site.

  - MFSA 2007-15 / CVE-2007-1558 :

    Ga&euml;tan Leurent informed us of a weakness in APOP
    authentication that could allow an attacker to recover
    the first part of your mail password if the attacker
    could interpose a malicious mail server on your network
    masquerading as your legitimate mail server. With normal
    settings it could take several hours for the attacker to
    gather enough data to recover just a few characters of
    the password. This result was presented at the Fast
    Software Encryption 2007 conference. 

  - MFSA 2007-14 / CVE-2007-1362 :

    Nicolas Derouet reported two problems with cookie
    handling in Mozilla clients. Insufficient length checks
    could be use to exhaust browser memory and so to crash
    the browser or at least slow it done by a large degree.

    The second issue was that the cookie path and name
    values were not checked for the presence of the
    delimiter used for internal cookie storage, and if
    present this confused future interpretation of the
    cookie data. This is not considered to be exploitable.

  - MFSA 2007-13 / CVE-2007-2869 :

    Marcel reported that a malicious web page could perform
    a denial of service attack against the form autocomplete
    feature that would persist from session to session until
    the malicious form data was deleted. Filling a text
    field with millions of characters and submitting the
    form will cause the victim's browser to hang for up to
    several minutes while the form data is read, and this
    will happen the first time autocomplete is triggered
    after every browser restart. 

    No harm is done to the user's computer, but the
    frustration caused by the hang could prevent use of
    Thunderbird if users don't know how to clear the bad
    state.

  - MFSA 2007-12 / CVE-2007-2867 / CVE-2007-2868

    As part of the Thunderbird 2.0.0.4 and 1.5.0.12 update
    releases Mozilla developers fixed many bugs to improve
    the stability of the product. Some of these crashes that
    showed evidence of memory corruption under certain
    circumstances and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. 

    Without further investigation we cannot rule out the
    possibility that for some of these an attacker might be
    able to prepare memory for exploitation through some
    means other than JavaScript, such as large images.

  - MFSA 2007-11 / CVE-2007-1562 :

    Incorrect FTP PASV handling could be used by malicious
    ftp servers to do a rudimentary port scanning of for
    instance internal networks of the computer the browser
    is running on."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-spellchecker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/11");
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
if (release !~ "^(SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"seamonkey-1.1.2-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"seamonkey-dom-inspector-1.1.2-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"seamonkey-irc-1.1.2-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"seamonkey-mail-1.1.2-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"seamonkey-spellchecker-1.1.2-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"seamonkey-venkman-1.1.2-1.1") ) flag++;

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
