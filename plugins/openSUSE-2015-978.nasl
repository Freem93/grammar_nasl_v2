#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-978.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87717);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-7575");

  script_name(english:"openSUSE Security Update : mozilla-nss (openSUSE-2015-978) (SLOTH)");
  script_summary(english:"Check for the openSUSE-2015-978 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to mozilla-nss 3.20.2 fixes the following issues :

  - CVE-2015-7575: MD5 signatures accepted within TLS 1.2
    ServerKeyExchange in server signature (boo#952810)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959888"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/31");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-debuginfo-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-debuginfo-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-debuginfo-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debuginfo-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debugsource-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-devel-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-debuginfo-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-debuginfo-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.20.2-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfreebl3-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfreebl3-debuginfo-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsoftokn3-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsoftokn3-debuginfo-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-certs-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-certs-debuginfo-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-debuginfo-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-debugsource-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-devel-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-sysinit-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-sysinit-debuginfo-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-tools-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-tools-debuginfo-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfreebl3-32bit-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.20.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libfreebl3-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libfreebl3-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsoftokn3-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsoftokn3-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-certs-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-certs-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-debugsource-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-devel-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-sysinit-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-sysinit-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-tools-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-tools-debuginfo-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.20.2-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.20.2-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libfreebl3 / libfreebl3-32bit / libfreebl3-debuginfo / etc");
}
