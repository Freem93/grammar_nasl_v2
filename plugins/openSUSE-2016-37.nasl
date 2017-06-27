#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-37.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88127);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/01/25 16:37:21 $");

  script_name(english:"openSUSE Security Update : libebml / libmatroska (openSUSE-2016-37)");
  script_summary(english:"Check for the openSUSE-2016-37 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libebml, libmatroska fixes the following security
issues :

Vulnerabilities fixed in libebml :

  - Cisco TALOS-CAN-0036: Invalid memory access when reading
    from a UTF-8 string resulted in a heap information leak
    (bsc#961031).

  - Cisco TALOS-CAN-0037: Deeply nested elements with
    infinite size use-after-free and multiple free
    (bsc#961031).

  - Invalid mempry access resulted in heap information leak

Vulnerabilities fixed in libmatroska :

  - invalid memory access when reading specially crafted
    data lead to a heap information leak."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961031"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libebml / libmatroska packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebml-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebml-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebml4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebml4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebml4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebml4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmatroska-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmatroska-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmatroska6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmatroska6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmatroska6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmatroska6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/25");
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

if ( rpm_check(release:"SUSE13.1", reference:"libebml-debugsource-1.3.3-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libebml-devel-1.3.3-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libebml4-1.3.3-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libebml4-debuginfo-1.3.3-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmatroska-debugsource-1.4.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmatroska-devel-1.4.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmatroska6-1.4.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmatroska6-debuginfo-1.4.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libebml4-32bit-1.3.3-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libebml4-debuginfo-32bit-1.3.3-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmatroska6-32bit-1.4.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmatroska6-debuginfo-32bit-1.4.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libebml-debugsource-1.3.3-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libebml-devel-1.3.3-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libebml4-1.3.3-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libebml4-debuginfo-1.3.3-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmatroska-debugsource-1.4.4-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmatroska-devel-1.4.4-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmatroska6-1.4.4-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmatroska6-debuginfo-1.4.4-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libebml4-32bit-1.3.3-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libebml4-debuginfo-32bit-1.3.3-9.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmatroska6-32bit-1.4.4-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmatroska6-debuginfo-32bit-1.4.4-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libebml-debugsource-1.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libebml-devel-1.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libebml4-1.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libebml4-debuginfo-1.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmatroska-debugsource-1.4.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmatroska-devel-1.4.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmatroska6-1.4.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmatroska6-debuginfo-1.4.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libebml4-32bit-1.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libebml4-debuginfo-32bit-1.3.3-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmatroska6-32bit-1.4.4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmatroska6-debuginfo-32bit-1.4.4-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libebml-debugsource / libebml-devel / libebml4 / libebml4-32bit / etc");
}
