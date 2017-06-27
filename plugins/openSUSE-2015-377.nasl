#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-377.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83803);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/26 13:52:13 $");

  script_cve_id("CVE-2014-4607");

  script_name(english:"openSUSE Security Update : LibVNCServer (openSUSE-2015-377)");
  script_summary(english:"Check for the openSUSE-2015-377 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibVNCServer was updated to version 0.9.10 to fix several security and
non-security issues.

The following issues were fixed :

  - Remove xorg-x11-devel from buildRequires, X libraries
    are not directly used/linked

  - libvncserver-0.9.10-ossl.patch: Update, do not
    RAND_load_file('/dev/urandom', 1024) if the the PRNG is
    already seeded. (It always is on linux)

  - Update to version 0.9.10

  + Moved the whole project from sourceforge to
    https://libvnc.github.io/.

  + Cleaned out the autotools build system which now uses
    autoreconf.

  + Updated noVNC HTML5 client to latest version.

  + Split out x11vnc sources into separate repository at
    https://github.com/LibVNC/x11vnc

  + Split out vncterm sources into separate repository at
    https://github.com/LibVNC/vncterm

  + Split out VisualNaCro sources into separate repository
    at https://github.com/LibVNC/VisualNaCro

  + Merged Debian patches.

  + Fixed some security-related buffer overflow cases.

  + Added compatibility headers to make
    LibVNCServer/LibVNCClient build on native Windows 8.

  + Update LZO to version 2.07, fixing CVE-2014-4607.

  + Merged patches from KDE/krfb.

  + Can now do IPv6 without IPv4.

  + Fixed a use-after-free issue in scale.c.

  - Update Url and download source to new project home

  - Remove LibVNCServer-0.9.9-no_x11vnc.patch; upstream
    splited it out of main tarball

  - Rebase libvncserver-ossl.patch to upstream changes >
    libvncserver-0.9.10-ossl.patch

  - Remove linuxvnc subpackage; like x11vnc, it has been
    splited out but is depreciated and unmaintained."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/LibVNC/VisualNaCro"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/LibVNC/vncterm"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/LibVNC/x11vnc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://libvnc.github.io/."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected LibVNCServer packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:LibVNCServer-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:LibVNCServer-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvncclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvncclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvncserver0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvncserver0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/26");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"LibVNCServer-debugsource-0.9.10-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"LibVNCServer-devel-0.9.10-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvncclient0-0.9.10-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvncclient0-debuginfo-0.9.10-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvncserver0-0.9.10-10.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libvncserver0-debuginfo-0.9.10-10.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibVNCServer-debugsource / LibVNCServer-devel / libvncclient0 / etc");
}
