#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-289.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97369);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/24 15:07:16 $");

  script_cve_id("CVE-2016-10166", "CVE-2016-10167", "CVE-2016-10168", "CVE-2016-6906", "CVE-2016-6912", "CVE-2016-9317");

  script_name(english:"openSUSE Security Update : gd (openSUSE-2017-289)");
  script_summary(english:"Check for the openSUSE-2017-289 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gd fixes the following security issues :

  - CVE-2016-6906: An out-of-bounds read in TGA
    decompression was fixed which could have lead to
    crashes. (bsc#1022553)

  - CVE-2016-6912: Double free vulnerability in the
    gdImageWebPtr function in the GD Graphics Library (aka
    libgd) allowed remote attackers to have unspecified
    impact via large width and height values. (bsc#1022284)

  - CVE-2016-9317: The gdImageCreate function in the GD
    Graphics Library (aka libgd) allowed remote attackers to
    cause a denial of service (system hang) via an oversized
    image. (bsc#1022283)

  - CVE-2016-10166: A potential unsigned underflow in gd
    interpolation functions could lead to memory corruption
    in the GD Graphics Library (aka libgd) (bsc#1022263)

  - CVE-2016-10167: A denial of service problem in
    gdImageCreateFromGd2Ctx() could lead to libgd running
    out of memory even on small files. (bsc#1022264)

  - CVE-2016-10168: A signed integer overflow in the GD
    Graphics Library (aka libgd) could lead to memory
    corruption (bsc#1022265)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022553"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gd-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/24");
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

if ( rpm_check(release:"SUSE42.1", reference:"gd-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gd-debuginfo-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gd-debugsource-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"gd-devel-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gd-32bit-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"gd-debuginfo-32bit-2.1.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gd-2.1.0-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gd-debuginfo-2.1.0-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gd-debugsource-2.1.0-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"gd-devel-2.1.0-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"gd-32bit-2.1.0-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"gd-debuginfo-32bit-2.1.0-16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gd / gd-32bit / gd-debuginfo / gd-debuginfo-32bit / gd-debugsource / etc");
}
