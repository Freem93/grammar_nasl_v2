#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-454.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90523);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/04/27 13:33:46 $");

  script_cve_id("CVE-2016-2347");

  script_name(english:"openSUSE Security Update : lhasa (openSUSE-2016-454)");
  script_summary(english:"Check for the openSUSE-2016-454 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for lhasa to 0.3.1 fixes the following issues :

These security issues were fixed :

  - CVE-2016-2347: Integer underflow vulnerability in the
    code for doing LZH level 3 header decodes (boo#973790)[

These non-security issues were fixed :

  - PMarc -pm1- archives that contain truncated compressed
    data (the decompressed length is longer than what can be
    read from the compressed data) now decompress as
    intended. Certain archives in the wild make the
    assumption that this can be done.

  - LArc -lz5- archives that make use of the initial history
    buffer now decompress correctly.

  - The tests no longer use predictable temporary paths."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973790"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lhasa packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lhasa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lhasa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lhasa-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lhasa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblhasa0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblhasa0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"lhasa-0.3.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"lhasa-debuginfo-0.3.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"lhasa-debugsource-0.3.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"lhasa-devel-0.3.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"liblhasa0-0.3.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"liblhasa0-debuginfo-0.3.1-4.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lhasa / lhasa-debuginfo / lhasa-debugsource / lhasa-devel / etc");
}
