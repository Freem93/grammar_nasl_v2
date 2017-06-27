#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-736-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37956);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:37:18 $");

  script_cve_id("CVE-2009-0386", "CVE-2009-0387", "CVE-2009-0397");
  script_bugtraq_id(33405);
  script_osvdb_id(53550);
  script_xref(name:"USN", value:"736-1");

  script_name(english:"Ubuntu 7.10 / 8.04 LTS / 8.10 : gst-plugins-good0.10 vulnerabilities (USN-736-1)");
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
"It was discovered that GStreamer Good Plugins did not correctly handle
malformed Composition Time To Sample (ctts) atom data in Quicktime
(mov) movie files. If a user were tricked into opening a crafted mov
file, an attacker could execute arbitrary code with the privileges of
the user invoking the program. (CVE-2009-0386)

It was discovered that GStreamer Good Plugins did not correctly handle
malformed Sync Sample (aka stss) atom data in Quicktime (mov) movie
files. If a user were tricked into opening a crafted mov file, an
attacker could cause a denial of service via application crash, or
possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2009-0387)

It was discovered that GStreamer Good Plugins did not correctly handle
malformed Time-to-sample (aka stts) atom data in Quicktime (mov) movie
files. If a user were tricked into opening a crafted mov file, an
attacker could execute arbitrary code with the privileges of the user
invoking the program. (CVE-2009-0397).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-esd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-plugins-good-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-plugins-good-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer0.10-pulseaudio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! ereg(pattern:"^(7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.10", pkgname:"gstreamer0.10-esd", pkgver:"0.10.6-0ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gstreamer0.10-plugins-good", pkgver:"0.10.6-0ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gstreamer0.10-plugins-good-dbg", pkgver:"0.10.6-0ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gstreamer0.10-plugins-good-doc", pkgver:"0.10.6-0ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gstreamer0.10-esd", pkgver:"0.10.7-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gstreamer0.10-plugins-good", pkgver:"0.10.7-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gstreamer0.10-plugins-good-dbg", pkgver:"0.10.7-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gstreamer0.10-plugins-good-doc", pkgver:"0.10.7-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gstreamer0.10-esd", pkgver:"0.10.10.4-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gstreamer0.10-plugins-good", pkgver:"0.10.10.4-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gstreamer0.10-plugins-good-dbg", pkgver:"0.10.10.4-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gstreamer0.10-plugins-good-doc", pkgver:"0.10.10.4-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gstreamer0.10-pulseaudio", pkgver:"0.10.10.4-1ubuntu1.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
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
