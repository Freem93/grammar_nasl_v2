#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1214.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94220);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/21 14:22:37 $");

  script_cve_id("CVE-2016-5407", "CVE-2016-7942", "CVE-2016-7944", "CVE-2016-7945", "CVE-2016-7946", "CVE-2016-7947", "CVE-2016-7948", "CVE-2016-7949", "CVE-2016-7950", "CVE-2016-7951", "CVE-2016-7952", "CVE-2016-7953");

  script_name(english:"openSUSE Security Update : X Window System client libraries (openSUSE-2016-1214)");
  script_summary(english:"Check for the openSUSE-2016-1214 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for the X Window System client libraries fixes a class of
privilege escalation issues.

A malicious X Server could send specially crafted data to X clients,
which allowed for triggering crashes, or privilege escalation if this
relationship was untrusted or crossed user or permission level
boundaries.

libX11, libXfixes, libXi, libXrandr, libXrender, libXtst, libXv,
libXvMC were fixed, specifically :

libX11 :

  - CVE-2016-7942: insufficient validation of data from the
    X server allowed out of boundary memory read
    (bsc#1002991)

libXfixes :

  - CVE-2016-7944: insufficient validation of data from the
    X server can cause an integer overflow on 32 bit
    architectures (bsc#1002995)

libXi :

  - CVE-2016-7945, CVE-2016-7946: insufficient validation of
    data from the X server can cause out of boundary memory
    access or endless loops (Denial of Service)
    (bsc#1002998)

libXtst :

  - CVE-2016-7951, CVE-2016-7952: insufficient validation of
    data from the X server can cause out of boundary memory
    access or endless loops (Denial of Service)
    (bsc#1003012)

libXv :

  - CVE-2016-5407: insufficient validation of data from the
    X server can cause out of boundary memory and memory
    corruption (bsc#1003017)

libXvMC :

  - CVE-2016-7953: insufficient validation of data from the
    X server can cause a one byte buffer read underrun
    (bsc#1003023)

libXrender :

  - CVE-2016-7949, CVE-2016-7950: insufficient validation of
    data from the X server can cause out of boundary memory
    writes (bsc#1003002)

libXrandr :

  - CVE-2016-7947, CVE-2016-7948: insufficient validation of
    data from the X server can cause out of boundary memory
    writes (bsc#1003000)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003023"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected X Window System client libraries packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfixes-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfixes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfixes-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfixes3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfixes3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfixes3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfixes3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXi6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrandr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrandr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrandr-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrandr2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrandr2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrandr2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrandr2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrender-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrender-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrender-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrender1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrender1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrender1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXrender1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXtst-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXtst-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXtst-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXtst6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXtst6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXtst6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXtst6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXv-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXv1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXv1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXv1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXv1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/24");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libX11-6-1.6.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libX11-6-debuginfo-1.6.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libX11-data-1.6.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libX11-debugsource-1.6.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libX11-devel-1.6.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libX11-xcb1-1.6.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libX11-xcb1-debuginfo-1.6.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXfixes-debugsource-5.0.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXfixes-devel-5.0.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXfixes3-5.0.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXfixes3-debuginfo-5.0.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXi-debugsource-1.7.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXi-devel-1.7.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXi6-1.7.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXi6-debuginfo-1.7.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXrandr-debugsource-1.5.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXrandr-devel-1.5.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXrandr2-1.5.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXrandr2-debuginfo-1.5.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXrender-debugsource-0.9.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXrender-devel-0.9.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXrender1-0.9.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXrender1-debuginfo-0.9.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXtst-debugsource-1.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXtst-devel-1.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXtst6-1.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXtst6-debuginfo-1.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXv-debugsource-1.0.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXv-devel-1.0.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXv1-1.0.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXv1-debuginfo-1.0.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXvMC-debugsource-1.0.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXvMC-devel-1.0.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXvMC1-1.0.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXvMC1-debuginfo-1.0.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libX11-6-32bit-1.6.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libX11-6-debuginfo-32bit-1.6.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libX11-devel-32bit-1.6.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libX11-xcb1-32bit-1.6.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libX11-xcb1-debuginfo-32bit-1.6.3-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXfixes-devel-32bit-5.0.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXfixes3-32bit-5.0.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXfixes3-debuginfo-32bit-5.0.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXi-devel-32bit-1.7.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXi6-32bit-1.7.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXi6-debuginfo-32bit-1.7.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXrandr-devel-32bit-1.5.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXrandr2-32bit-1.5.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXrandr2-debuginfo-32bit-1.5.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXrender-devel-32bit-0.9.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXrender1-32bit-0.9.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXrender1-debuginfo-32bit-0.9.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXtst-devel-32bit-1.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXtst6-32bit-1.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXtst6-debuginfo-32bit-1.2.2-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXv-devel-32bit-1.0.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXv1-32bit-1.0.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXv1-debuginfo-32bit-1.0.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXvMC-devel-32bit-1.0.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXvMC1-32bit-1.0.9-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXvMC1-debuginfo-32bit-1.0.9-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libX11-6 / libX11-6-32bit / libX11-6-debuginfo / etc");
}
