#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-212.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88772);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2015-8803", "CVE-2015-8804", "CVE-2015-8805");

  script_name(english:"openSUSE Security Update : libnettle (openSUSE-2016-212)");
  script_summary(english:"Check for the openSUSE-2016-212 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libnettle fixes the following security issues :

  - CVE-2015-8803: Fixed miscomputation bugs in secp-256r1
    modulo functions. (bsc#964845)

  - CVE-2015-8804: Fixed carry folding bug in x86_64
    ecc_384_modp. (bsc#964847)

  - CVE-2015-8805: Fixed miscomputation bugs in secp-256r1
    modulo functions. (bsc#964849)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964849"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libnettle packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhogweed2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhogweed2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhogweed2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhogweed2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnettle4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nettle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nettle-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libhogweed2-2.7.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libhogweed2-debuginfo-2.7.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnettle-debugsource-2.7.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnettle-devel-2.7.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnettle4-2.7.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libnettle4-debuginfo-2.7.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nettle-2.7.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nettle-debuginfo-2.7.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libhogweed2-32bit-2.7.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libhogweed2-debuginfo-32bit-2.7.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libnettle-devel-32bit-2.7.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libnettle4-32bit-2.7.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libnettle4-debuginfo-32bit-2.7.1-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libhogweed2 / libhogweed2-32bit / libhogweed2-debuginfo / etc");
}
