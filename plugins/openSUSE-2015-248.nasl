#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-248.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(82012);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/24 13:22:29 $");

  script_cve_id("CVE-2013-0211", "CVE-2015-2304");

  script_name(english:"openSUSE Security Update : libarchive (openSUSE-2015-248)");
  script_summary(english:"Check for the openSUSE-2015-248 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libarchive was updated to fix a directory traversal in the bsdcpio
tool, which allowed attackers supplying crafted archives to overwrite
files. (CVE-2015-2304)

Also, a integer overflow was fixed that could also overflow buffers.
(CVE-2013-0211)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=800024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920870"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libarchive packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bsdtar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bsdtar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive13-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive13-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libarchive13-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");
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

if ( rpm_check(release:"SUSE13.1", reference:"bsdtar-3.1.2-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bsdtar-debuginfo-3.1.2-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libarchive-debugsource-3.1.2-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libarchive-devel-3.1.2-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libarchive13-3.1.2-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libarchive13-debuginfo-3.1.2-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libarchive13-32bit-3.1.2-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libarchive13-debuginfo-32bit-3.1.2-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bsdtar-3.1.2-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bsdtar-debuginfo-3.1.2-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libarchive-debugsource-3.1.2-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libarchive-devel-3.1.2-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libarchive13-3.1.2-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libarchive13-debuginfo-3.1.2-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libarchive13-32bit-3.1.2-7.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libarchive13-debuginfo-32bit-3.1.2-7.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bsdtar / bsdtar-debuginfo / libarchive-debugsource / etc");
}
