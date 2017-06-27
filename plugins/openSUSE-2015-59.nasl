#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-59.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80990);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/11 13:51:33 $");

  script_cve_id("CVE-2014-9447");

  script_name(english:"openSUSE Security Update : elfutils (openSUSE-SU-2015:0123-1)");
  script_summary(english:"Check for the openSUSE-2015-59 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"elfutils was updated to fix a directory traversal vulnerability
(bnc#911662 CVE-2014-9447)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2015-01/msg00063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911662"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected elfutils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:elfutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:elfutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasm1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libasm1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdw1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdw1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdw1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdw1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebl1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebl1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebl1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libelf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libelf-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libelf1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libelf1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libelf1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libelf1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/26");
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

if ( rpm_check(release:"SUSE13.1", reference:"elfutils-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"elfutils-debuginfo-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"elfutils-debugsource-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libasm-devel-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libasm1-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libasm1-debuginfo-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdw-devel-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdw1-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdw1-debuginfo-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libebl-devel-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libebl1-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libebl1-debuginfo-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libelf-devel-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libelf1-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libelf1-debuginfo-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libasm1-32bit-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libasm1-debuginfo-32bit-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdw1-32bit-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdw1-debuginfo-32bit-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libebl1-32bit-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libebl1-debuginfo-32bit-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libelf-devel-32bit-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libelf1-32bit-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libelf1-debuginfo-32bit-0.155-6.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"elfutils-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"elfutils-debuginfo-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"elfutils-debugsource-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libasm-devel-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libasm1-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libasm1-debuginfo-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdw-devel-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdw1-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libdw1-debuginfo-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libebl-devel-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libebl1-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libebl1-debuginfo-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libelf-devel-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libelf1-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libelf1-debuginfo-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libasm1-32bit-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libasm1-debuginfo-32bit-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdw1-32bit-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libdw1-debuginfo-32bit-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libebl1-32bit-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libebl1-debuginfo-32bit-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libelf-devel-32bit-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libelf1-32bit-0.158-4.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libelf1-debuginfo-32bit-0.158-4.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "elfutils / elfutils-debuginfo / elfutils-debugsource / libasm-devel / etc");
}
