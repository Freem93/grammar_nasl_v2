#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-266.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(82424);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/30 13:59:01 $");

  script_cve_id("CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");

  script_name(english:"openSUSE Security Update : libXfont (openSUSE-2015-266)");
  script_summary(english:"Check for the openSUSE-2015-266 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libXFont was updated to fix three vulnerabilities when parsing BDF
files (bnc#921978)

As libXfont is used by the X server to read font files, and an
unprivileged user with access to the X server can tell the X server to
read a given font file from a path of their choosing, these
vulnerabilities have the potential to allow unprivileged users to run
code with the privileges of the X server.

The following vulnerabilities were fixed :

  - The BDF parser could allocate the a wrong buffer size,
    leading to out of bound writes (CVE-2015-1802)

  - The BDF parser could crash when trying to read an
    invalid pointer (CVE-2015-1803)

  - The BDF parser could read 32 bit metrics values into 16
    bit integers, causing an out-of-bound memory access
    though integer overflow (CVE-2015-1804)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=921978"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libXfont packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
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

if ( rpm_check(release:"SUSE13.1", reference:"libXfont-debugsource-1.4.6-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont-devel-1.4.6-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont1-1.4.6-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont1-debuginfo-1.4.6-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libXfont-devel-32bit-1.4.6-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libXfont1-32bit-1.4.6-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libXfont1-debuginfo-32bit-1.4.6-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXfont-debugsource-1.5.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXfont-devel-1.5.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXfont1-1.5.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXfont1-debuginfo-1.5.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libXfont-devel-32bit-1.5.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libXfont1-32bit-1.5.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libXfont1-debuginfo-32bit-1.5.0-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libXfont-debugsource / libXfont-devel / libXfont-devel-32bit / etc");
}
