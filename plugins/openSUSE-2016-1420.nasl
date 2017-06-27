#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1420.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95644);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/21 14:22:37 $");

  script_cve_id("CVE-2016-7942", "CVE-2016-7945", "CVE-2016-7946", "CVE-2016-7947", "CVE-2016-7948");

  script_name(english:"openSUSE Security Update : X Window System client libraries (openSUSE-2016-1420)");
  script_summary(english:"Check for the openSUSE-2016-1420 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for X Window System client libraries fixes a class of
privilege escalation issues.

A malicious X server could send specially crafted data to X clients,
which allowed for triggering crashes, or privilege escalation if this
relationship was untrusted or crossed user or permission level
boundaries.

The following libraries have been fixed :

libX11 :

  - plugged a memory leak (boo#1002991, CVE-2016-7942).

  - insufficient validation of data from the X server can
    cause out of boundary memory read (XGetImage()) or write
    (XListFonts()) (boo#1002991, CVE-2016-7942).

libXi :

  - Integer overflows in libXi can cause out of boundary
    memory access or endless loops (Denial of Service)
    (boo#1002998, CVE-2016-7945).

  - Insufficient validation of data in libXi can cause out
    of boundary memory access or endless loops (Denial of
    Service) (boo#1002998, CVE-2016-7946).

libXrandr :

  - Insufficient validation of data from the X server can
    cause out of boundary memory writes (boo#1003000,
    CVE-2016-7947, CVE-2016-7948)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002991"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-composite0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-composite0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-composite0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-composite0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-damage0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-damage0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-damage0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-damage0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dpms0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dpms0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dpms0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dpms0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri2-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri2-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri2-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri3-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri3-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri3-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-glx0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-glx0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-glx0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-glx0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-present0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-present0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-present0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-present0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-randr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-randr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-randr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-randr0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-record0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-record0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-record0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-record0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-render0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-render0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-render0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-render0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-res0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-res0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-res0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-res0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-screensaver0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-screensaver0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-screensaver0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-screensaver0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shape0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shape0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shape0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shape0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shm0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shm0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shm0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shm0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-sync1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-sync1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-sync1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-sync1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xevie0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xevie0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xevie0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xevie0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xf86dri0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xf86dri0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xf86dri0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xf86dri0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xfixes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xfixes0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xfixes0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xfixes0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinerama0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinerama0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinerama0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinerama0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xkb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xkb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xkb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xkb1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xprint0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xprint0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xprint0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xprint0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xtest0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xtest0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xtest0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xtest0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xv0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xv0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xv0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xv0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xvmc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xvmc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xvmc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xvmc0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/08");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libX11-6-1.6.2-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libX11-6-debuginfo-1.6.2-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libX11-data-1.6.2-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libX11-debugsource-1.6.2-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libX11-devel-1.6.2-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libX11-xcb1-1.6.2-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libX11-xcb1-debuginfo-1.6.2-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXi-debugsource-1.7.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXi-devel-1.7.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXi6-1.7.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXi6-debuginfo-1.7.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXrandr-debugsource-1.4.2-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXrandr-devel-1.4.2-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXrandr2-1.4.2-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXrandr2-debuginfo-1.4.2-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-composite0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-composite0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-damage0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-damage0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-debugsource-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-devel-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-dpms0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-dpms0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-dri2-0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-dri2-0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-dri3-0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-dri3-0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-glx0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-glx0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-present0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-present0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-randr0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-randr0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-record0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-record0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-render0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-render0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-res0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-res0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-screensaver0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-screensaver0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-shape0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-shape0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-shm0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-shm0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-sync1-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-sync1-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xevie0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xevie0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xf86dri0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xf86dri0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xfixes0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xfixes0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xinerama0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xinerama0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xkb1-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xkb1-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xprint0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xprint0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xtest0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xtest0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xv0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xv0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xvmc0-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb-xvmc0-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb1-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libxcb1-debuginfo-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libX11-6-32bit-1.6.2-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libX11-6-debuginfo-32bit-1.6.2-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libX11-devel-32bit-1.6.2-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libX11-xcb1-32bit-1.6.2-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libX11-xcb1-debuginfo-32bit-1.6.2-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libXi-devel-32bit-1.7.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libXi6-32bit-1.7.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libXi6-debuginfo-32bit-1.7.4-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libXrandr-devel-32bit-1.4.2-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libXrandr2-32bit-1.4.2-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libXrandr2-debuginfo-32bit-1.4.2-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-composite0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-composite0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-damage0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-damage0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-devel-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-dpms0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-dpms0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-dri2-0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-dri2-0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-dri3-0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-dri3-0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-glx0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-glx0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-present0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-present0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-randr0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-randr0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-record0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-record0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-render0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-render0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-res0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-res0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-screensaver0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-screensaver0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-shape0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-shape0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-shm0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-shm0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-sync1-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-sync1-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xevie0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xevie0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xf86dri0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xf86dri0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xfixes0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xfixes0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xinerama0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xinerama0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xkb1-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xkb1-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xprint0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xprint0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xtest0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xtest0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xv0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xv0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xvmc0-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb-xvmc0-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb1-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libxcb1-debuginfo-32bit-1.11-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libX11-6-1.6.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libX11-6-debuginfo-1.6.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libX11-data-1.6.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libX11-debugsource-1.6.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libX11-devel-1.6.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libX11-xcb1-1.6.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libX11-xcb1-debuginfo-1.6.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXi-debugsource-1.7.5-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXi-devel-1.7.5-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXi6-1.7.5-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXi6-debuginfo-1.7.5-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libX11-6-32bit-1.6.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libX11-6-debuginfo-32bit-1.6.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libX11-devel-32bit-1.6.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libX11-xcb1-32bit-1.6.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libX11-xcb1-debuginfo-32bit-1.6.3-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXi-devel-32bit-1.7.5-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXi6-32bit-1.7.5-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXi6-debuginfo-32bit-1.7.5-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libXrandr-debugsource-1.5.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libXrandr-devel-1.5.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libXrandr2-1.5.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libXrandr2-debuginfo-1.5.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libXrandr-devel-32bit-1.5.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libXrandr2-32bit-1.5.0-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libXrandr2-debuginfo-32bit-1.5.0-5.1") ) flag++;

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
