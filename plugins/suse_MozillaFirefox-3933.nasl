#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-3933.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27122);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2007-3089", "CVE-2007-3285", "CVE-2007-3656", "CVE-2007-3670", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");

  script_name(english:"openSUSE 10 Security Update : MozillaFirefox (MozillaFirefox-3933)");
  script_summary(english:"Check for the MozillaFirefox-3933 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Firefox to security update version 2.0.0.5

Following security problems were fixed :

  - MFSA 2007-18: Crashes with evidence of memory corruption

    The usual collection of stability fixes for crashes that
    look suspicious but haven't been proven to be
    exploitable.

    25 were in the browser engine, reported by Mozilla
    developers and community members Bernd Mielke, Boris
    Zbarsky, David Baron, Daniel Veditz, Jesse Ruderman,
    Lukas Loehrer, Martijn Wargers, Mats Palmgren, Olli
    Pettay, Paul Nickerson,and Vladimir Sukhoy
    (CVE-2007-3734)

    7 were in the JavaScript engine reported by Asaf Romano,
    Jesse Ruderman, Igor Bukanov (CVE-2007-3735)

  - MFSA 2007-19 / CVE-2007-3736: XSS using addEventListener
    and setTimeout

    moz_bug_r_a4 reported that scripts could be injected
    into another site's context by exploiting a timing issue
    using addEventLstener or setTimeout.

  - MFSA 2007-20 / CVE-2007-3089: frame spoofing

    Ronen Zilberman and Michal Zalewski both reported that
    it was possible to exploit a timing issue to inject
    content into about:blank frames in a page.

  - MFSA 2007-21 / CVE-2007-3737: Privilege escalation using
    an event handler attached to an element not in the
    document

    Reported by moz_bug_r_a4.

  - MFSA 2007-22 / CVE-2007-3285: File type confusion due to
    %00 in name

    Ronald van den Heetkamp reported that a filename URL
    containing %00 (encoded null) can cause Firefox to
    interpret the file extension differently than the
    underlying Windows operating system potentially leading
    to unsafe actions such as running a program.

  - MFSA 2007-23 / CVE-2007-3670: Remote code execution by
    launching Firefox from Internet Explorer

    Greg MacManus of iDefense and Billy Rios of Verisign
    independently reported that links containing a quote (')
    character could be used in Internet Explorer to launch
    registered URL Protocol handlers with extra command-line
    parameters. Firefox and Thunderbird are among those
    which can be launched, and both support a '-chrome'
    option that could be used to run malware.

    This problem does not affect Linux.

  - MFSA 2007-24 / CVE-2007-3656: unauthorized access to
    wyciwyg:// documents

    Michal Zalewski reported that it was possible to bypass
    the same-origin checks and read from cached (wyciwyg)
    documents

  - MFSA 2007-25 / CVE-2007-3738: XPCNativeWrapper pollution

    shutdown and moz_bug_r_a4 reported two separate ways to
    modify an XPCNativeWrapper such that subsequent access
    by the browser would result in executing user-supplied
    code."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/24");
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

if ( rpm_check(release:"SUSE10.2", reference:"MozillaFirefox-2.0.0.5-1.1") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"MozillaFirefox-translations-2.0.0.5-1.1") ) flag++;

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
