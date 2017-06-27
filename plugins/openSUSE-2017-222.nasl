#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-222.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97076);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/09 15:07:54 $");

  script_cve_id("CVE-2016-7056");

  script_name(english:"openSUSE Security Update : libressl (openSUSE-2017-222)");
  script_summary(english:"Check for the openSUSE-2017-222 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libressl fixes the following issues :

  - CVE-2016-7056: Difficult to execute cache timing attack
    that may have allowed a local user to recover the
    private part from ECDSA P-256 keys (boo#1019334)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019334"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libressl packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto36-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto36-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto36-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto37-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto37-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto37-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl37-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl37-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl37-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl38-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl38-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl38-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls10-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls10-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls9-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls9-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libcrypto36-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcrypto36-debuginfo-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libressl-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libressl-debuginfo-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libressl-debugsource-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libressl-devel-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libssl37-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libssl37-debuginfo-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtls9-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libtls9-debuginfo-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libcrypto36-32bit-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libcrypto36-debuginfo-32bit-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libressl-devel-32bit-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libssl37-32bit-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libssl37-debuginfo-32bit-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtls9-32bit-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libtls9-debuginfo-32bit-2.3.0-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcrypto37-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcrypto37-debuginfo-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libressl-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libressl-debuginfo-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libressl-debugsource-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libressl-devel-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libssl38-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libssl38-debuginfo-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtls10-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtls10-debuginfo-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libcrypto37-32bit-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libcrypto37-debuginfo-32bit-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libressl-devel-32bit-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libssl38-32bit-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libssl38-debuginfo-32bit-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtls10-32bit-2.3.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtls10-debuginfo-32bit-2.3.4-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcrypto36 / libcrypto36-32bit / libcrypto36-debuginfo / etc");
}
