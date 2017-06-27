#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-554.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(100038);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/09 15:19:41 $");

  script_cve_id("CVE-2017-5974", "CVE-2017-5975", "CVE-2017-5976", "CVE-2017-5977", "CVE-2017-5978", "CVE-2017-5979", "CVE-2017-5980", "CVE-2017-5981");

  script_name(english:"openSUSE Security Update : zziplib (openSUSE-2017-554)");
  script_summary(english:"Check for the openSUSE-2017-554 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for zziplib fixes the following issues :

Secuirty issues fixed :

  - CVE-2017-5974: heap-based buffer overflow in
    __zzip_get32 (fetch.c) (bsc#1024517)

  - CVE-2017-5975: heap-based buffer overflow in
    __zzip_get64 (fetch.c) (bsc#1024528)

  - CVE-2017-5976: heap-based buffer overflow in
    zzip_mem_entry_extra_block (memdisk.c) (bsc#1024531)

  - CVE-2017-5977: invalid memory read in
    zzip_mem_entry_extra_block (memdisk.c) (bsc#1024534)

  - CVE-2017-5978: out of bounds read in zzip_mem_entry_new
    (memdisk.c) (bsc#1024533)

  - CVE-2017-5979: NULL pointer dereference in prescan_entry
    (fseeko.c) (bsc#1024535)

  - CVE-2017-5980: NULL pointer dereference in
    zzip_mem_entry_new (memdisk.c) (bsc#1024536)

  - CVE-2017-5981: assertion failure in seeko.c
    (bsc#1024539)

  - NULL pointer dereference in main (unzzipcat-mem.c)
    (bsc#1024532)

  - NULL pointer dereference in main (unzzipcat.c)
    (bsc#1024537)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024539"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected zziplib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzzip-0-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzzip-0-13-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzzip-0-13-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzzip-0-13-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zziplib-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zziplib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zziplib-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zziplib-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zziplib-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");
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

if ( rpm_check(release:"SUSE42.1", reference:"libzzip-0-13-0.13.62-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libzzip-0-13-debuginfo-0.13.62-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"zziplib-debugsource-0.13.62-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"zziplib-devel-0.13.62-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"zziplib-devel-debuginfo-0.13.62-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libzzip-0-13-32bit-0.13.62-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libzzip-0-13-debuginfo-32bit-0.13.62-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"zziplib-devel-32bit-0.13.62-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"zziplib-devel-debuginfo-32bit-0.13.62-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzzip-0-13-0.13.62-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libzzip-0-13-debuginfo-0.13.62-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"zziplib-debugsource-0.13.62-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"zziplib-devel-0.13.62-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"zziplib-devel-debuginfo-0.13.62-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libzzip-0-13-32bit-0.13.62-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libzzip-0-13-debuginfo-32bit-0.13.62-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"zziplib-devel-32bit-0.13.62-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"zziplib-devel-debuginfo-32bit-0.13.62-10.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzzip-0-13 / libzzip-0-13-32bit / libzzip-0-13-debuginfo / etc");
}
