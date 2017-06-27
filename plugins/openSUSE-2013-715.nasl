#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-715.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75146);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/10 15:24:06 $");

  script_cve_id("CVE-2013-4231", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244");
  script_osvdb_id(96203, 96204, 96205, 96206, 96207, 96649, 96783);

  script_name(english:"openSUSE Security Update : tiff (openSUSE-SU-2013:1482-1)");
  script_summary(english:"Check for the openSUSE-2013-715 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This tiff security update fixes several buffer overflow issues and a
out-of-bounds wirte problem.

  - tiff: buffer overflows/use after free problem
    [CVE-2013-4231][CVE-2013-4232][bnc#834477]

  - libtiff (gif2tiff): OOB Write in LZW decompressor
    [CVE-2013-4244][bnc#834788]

  - libtiff (gif2tiff): heap-based buffer overflow in
    readgifimage() [CVE-2013-4243][bnc#834779]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-09/msg00051.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834788"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libtiff-devel-4.0.2-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libtiff5-4.0.2-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libtiff5-debuginfo-4.0.2-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tiff-4.0.2-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tiff-debuginfo-4.0.2-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tiff-debugsource-4.0.2-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.2-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libtiff5-32bit-4.0.2-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.2-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libtiff-devel-4.0.3-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libtiff5-4.0.3-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libtiff5-debuginfo-4.0.3-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tiff-4.0.3-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tiff-debuginfo-4.0.3-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tiff-debugsource-4.0.3-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.3-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libtiff5-32bit-4.0.3-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.3-2.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff-devel-32bit / libtiff-devel / libtiff5-32bit / libtiff5 / etc");
}
