#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-366.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83558);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/10/05 13:44:22 $");

  script_cve_id("CVE-2015-2170", "CVE-2015-2221", "CVE-2015-2222", "CVE-2015-2305", "CVE-2015-2668");

  script_name(english:"openSUSE Security Update : clamav (openSUSE-2015-366)");
  script_summary(english:"Check for the openSUSE-2015-366 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The ClamAV antivirus engine was updated to version 0.98.7 to fix
several security and non-security issues.

The following vulnerabilities were fixed (bsc#929192) :

  - CVE-2015-2170: Fix crash in upx decoder with crafted
    file. Discovered and patch supplied by Sebastian Andrzej
    Siewior.

  - CVE-2015-2221: Fix infinite loop condition on crafted
    y0da cryptor file. Identified and patch suggested by
    Sebastian Andrzej Siewior.

  - CVE-2015-2222: Fix crash on crafted petite packed file.
    Reported and patch supplied by Sebastian Andrzej
    Siewior.

  - CVE-2015-2668: Fix an infinite loop condition on a
    crafted 'xz' archive file. This was reported by Dimitri
    Kirchner and Goulven Guiheux.

  - CVE-2015-2305: Apply upstream patch for possible heap
    overflow in Henry Spencer's regex library.

The following bugfixes were applyed (bsc#929192) :

  - Fix false negatives on files within iso9660 containers.
    This issue was reported by Minzhuan Gong.

  - Fix a couple crashes on crafted upack packed file.
    Identified and patches supplied by Sebastian Andrzej
    Siewior.

  - Fix a crash during algorithmic detection on crafted PE
    file. Identified and patch supplied by Sebastian Andrzej
    Siewior.

  - Fix compilation error after ./configure
    --disable-pthreads. Reported and fix suggested by John
    E. Krokes.

  - Fix segfault scanning certain HTML files. Reported with
    sample by Kai Risku.

  - Improve detections within xar/pkg files.

  - Improvements to PDF processing: decryption, escape
    sequence handling, and file property collection.

  - Scanning/analysis of additional Microsoft Office 2003
    XML format."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=929192"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected clamav packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"clamav-0.98.7-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"clamav-debuginfo-0.98.7-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"clamav-debugsource-0.98.7-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"clamav-0.98.7-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"clamav-debuginfo-0.98.7-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"clamav-debugsource-0.98.7-2.16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / clamav-debuginfo / clamav-debugsource");
}
