#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-513.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99702);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/27 13:33:46 $");

  script_cve_id("CVE-2016-9586", "CVE-2017-7407");

  script_name(english:"openSUSE Security Update : curl (openSUSE-2017-513)");
  script_summary(english:"Check for the openSUSE-2017-513 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for curl fixes the following issues :

Security issue fixed :

  - CVE-2016-9586: libcurl printf floating point buffer
    overflow (bsc#1015332)

  - CVE-2017-7407: The ourWriteOut function in
    tool_writeout.c in curl might have allowed physically
    proximate attackers to obtain sensitive information from
    process memory in opportunistic circumstances by reading
    a workstation screen during use of a --write-out
    argument ending in a '%' character, which lead to a
    heap-based buffer over-read (bsc#1032309).

With this release new default ciphers are active (SUSE_DEFAULT,
bsc#1027712).

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032309"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/27");
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

if ( rpm_check(release:"SUSE42.1", reference:"curl-7.37.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"curl-debuginfo-7.37.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"curl-debugsource-7.37.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcurl-devel-7.37.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcurl4-7.37.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcurl4-debuginfo-7.37.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libcurl-devel-32bit-7.37.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libcurl4-32bit-7.37.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libcurl4-debuginfo-32bit-7.37.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"curl-7.37.0-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"curl-debuginfo-7.37.0-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"curl-debugsource-7.37.0-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcurl-devel-7.37.0-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcurl4-7.37.0-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcurl4-debuginfo-7.37.0-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libcurl-devel-32bit-7.37.0-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libcurl4-32bit-7.37.0-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libcurl4-debuginfo-32bit-7.37.0-16.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / curl-debugsource / libcurl-devel-32bit / etc");
}
