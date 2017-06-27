#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update seamonkey-5011.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(31113);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");

  script_name(english:"openSUSE 10 Security Update : seamonkey (seamonkey-5011)");
  script_summary(english:"Check for the seamonkey-5011 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update backports changes to Mozilla SeaMonkey to the level of the
security update version 1.8.1.12

Following security problems were fixed :

  - MFSA 2008-11/CVE-2008-0594 Web forgery overwrite with
    div overlay

  - MFSA 2008-10/CVE-2008-0593 URL token stealing via
    stylesheet redirect

  - MFSA 2008-09/CVE-2008-0592 Mishandling of locally-saved
    plain text files

  - MFSA 2008-08/CVE-2008-0591 File action dialog tampering

  - MFSA 2008-06/CVE-2008-0419 Web browsing history and
    forward navigation stealing

  - MFSA 2008-05/CVE-2008-0418 Directory traversal via
    chrome: URI

  - MFSA 2008-04/CVE-2008-0417 Stored password corruption

  - MFSA 2008-03/CVE-2008-0415 Privilege escalation, XSS,
    Remote Code Execution

  - MFSA 2008-02/CVE-2008-0414 Multiple file input focus
    stealing vulnerabilities

  - MFSA 2008-01/CVE-2008-0412/CVE-2008-0413 Crashes with
    evidence of memory corruption (rv:1.8.1.12)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 22, 79, 94, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-spellchecker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-1.0.9-1.10") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-calendar-1.0.9-1.10") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-dom-inspector-1.0.9-1.10") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-irc-1.0.9-1.10") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-mail-1.0.9-1.10") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-spellchecker-1.0.9-1.10") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"seamonkey-venkman-1.0.9-1.10") ) flag++;

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
