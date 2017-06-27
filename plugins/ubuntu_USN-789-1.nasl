#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-789-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39491);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:37:19 $");

  script_cve_id("CVE-2009-1932");
  script_xref(name:"USN", value:"789-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : gst-plugins-good0.10 vulnerability (USN-789-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tielei Wang discovered that GStreamer Good Plugins did not correctly
handle malformed PNG image files. If a user were tricked into opening
a crafted PNG image file with a GStreamer application, an attacker
could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the
program.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-esd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-plugins-good-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-plugins-good-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-pulseaudio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"gstreamer0.10-esd", pkgver:"0.10.3-0ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gstreamer0.10-plugins-good", pkgver:"0.10.3-0ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gstreamer0.10-plugins-good-dbg", pkgver:"0.10.3-0ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gstreamer0.10-plugins-good-doc", pkgver:"0.10.3-0ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gstreamer0.10-esd", pkgver:"0.10.7-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gstreamer0.10-plugins-good", pkgver:"0.10.7-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gstreamer0.10-plugins-good-dbg", pkgver:"0.10.7-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gstreamer0.10-plugins-good-doc", pkgver:"0.10.7-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gstreamer0.10-esd", pkgver:"0.10.10.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gstreamer0.10-plugins-good", pkgver:"0.10.10.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gstreamer0.10-plugins-good-dbg", pkgver:"0.10.10.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gstreamer0.10-plugins-good-doc", pkgver:"0.10.10.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gstreamer0.10-pulseaudio", pkgver:"0.10.10.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"gstreamer0.10-esd", pkgver:"0.10.14-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"gstreamer0.10-plugins-good", pkgver:"0.10.14-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"gstreamer0.10-plugins-good-dbg", pkgver:"0.10.14-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"gstreamer0.10-plugins-good-doc", pkgver:"0.10.14-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"gstreamer0.10-pulseaudio", pkgver:"0.10.14-1ubuntu0.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer0.10-esd / gstreamer0.10-plugins-good / etc");
}
