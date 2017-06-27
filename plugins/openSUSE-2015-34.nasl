#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-34.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80579);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/06 13:23:47 $");

  script_cve_id("CVE-2014-9114");

  script_name(english:"openSUSE Security Update : util-linux (openSUSE-SU-2015:0066-1)");
  script_summary(english:"Check for the openSUSE-2015-34 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"util-linux was updated to fix a security issue, where local attackers
might be able to execute code as root with a prepared USB stick
(CVE-2014-9114 bsc#907434)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2015-01/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907434"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libmount-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libmount-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uuidd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uuidd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"libblkid-devel-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libblkid1-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libblkid1-debuginfo-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmount-devel-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmount1-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmount1-debuginfo-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libuuid-devel-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libuuid1-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libuuid1-debuginfo-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"util-linux-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"util-linux-debuginfo-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"util-linux-debugsource-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"util-linux-lang-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"uuidd-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"uuidd-debuginfo-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libblkid-devel-32bit-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libblkid1-32bit-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libblkid1-debuginfo-32bit-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmount-devel-32bit-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmount1-32bit-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmount1-debuginfo-32bit-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libuuid-devel-32bit-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libuuid1-32bit-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libuuid1-debuginfo-32bit-2.23.2-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libblkid-devel-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libblkid-devel-static-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libblkid1-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libblkid1-debuginfo-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmount-devel-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmount-devel-static-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmount1-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmount1-debuginfo-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmartcols-devel-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmartcols-devel-static-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmartcols1-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsmartcols1-debuginfo-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libuuid-devel-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libuuid-devel-static-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libuuid1-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libuuid1-debuginfo-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-libmount-2.25.1-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-libmount-debuginfo-2.25.1-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-libmount-debugsource-2.25.1-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"util-linux-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"util-linux-debuginfo-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"util-linux-debugsource-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"util-linux-lang-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"util-linux-systemd-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"util-linux-systemd-debuginfo-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"util-linux-systemd-debugsource-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"uuidd-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"uuidd-debuginfo-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libblkid-devel-32bit-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libblkid1-32bit-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libblkid1-debuginfo-32bit-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmount-devel-32bit-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmount1-32bit-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmount1-debuginfo-32bit-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libuuid-devel-32bit-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libuuid1-32bit-2.25.1-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libuuid1-debuginfo-32bit-2.25.1-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libblkid-devel / libblkid-devel-32bit / libblkid1 / libblkid1-32bit / etc");
}
