#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update mozilla-xulrunner-5163.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(32025);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:42:28 $");

  script_cve_id("CVE-2007-4879", "CVE-2008-1195", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241");

  script_name(english:"openSUSE 10 Security Update : mozilla-xulrunner (mozilla-xulrunner-5163)");
  script_summary(english:"Check for the mozilla-xulrunner-5163 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings the Mozilla XULRunner engine to security update
version level 1.1.9

Following security problems were fixed :

  - MFSA 2008-19/CVE-2008-1241: XUL popup spoofing variant
    (cross-tab popups)

  - MFSA 2008-18/CVE-2008-1195 and CVE-2008-1240: Java
    socket connection to any local port via LiveConnect

  - MFSA 2008-17/CVE-2007-4879: Privacy issue with SSL
    Client Authentication

  - MFSA 2008-16/CVE-2008-1238: HTTP Referrer spoofing with
    malformed URLs

  - MFSA 2008-15/CVE-2008-1236 and CVE-2008-1237: Crashes
    with evidence of memory corruption (rv:1.8.1.13)

  - MFSA 2008-14/CVE-2008-1233, CVE-2008-1234, and
    CVE-2008-1235: JavaScript privilege escalation and
    arbitrary code execution."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-xulrunner packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(59, 79, 94, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:epiphany-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gecko-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/22");
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

if ( rpm_check(release:"SUSE10.1", reference:"epiphany-1.8.5-14.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"epiphany-devel-1.8.5-14.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"gecko-sdk-1.8.0.14eol-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mozilla-xulrunner-1.8.0.14eol-0.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"mozilla-xulrunner-32bit-1.8.0.14eol-0.5") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "epiphany / epiphany-devel / gecko-sdk / mozilla-xulrunner / etc");
}
