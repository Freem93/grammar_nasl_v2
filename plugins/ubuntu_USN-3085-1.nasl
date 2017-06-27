#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3085-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93648);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2015-7552", "CVE-2015-8875", "CVE-2016-6352");
  script_osvdb_id(133603, 138541, 142171);
  script_xref(name:"USN", value:"3085-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS : gdk-pixbuf vulnerabilities (USN-3085-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the GDK-PixBuf library did not properly handle
specially crafted bmp images, leading to a heap-based buffer overflow.
If a user or automated system were tricked into opening a specially
crafted bmp file, a remote attacker could use this flaw to cause
GDK-PixBuf to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS. (CVE-2015-7552)

It was discovered that the GDK-PixBuf library contained an integer
overflow when handling certain images. If a user or automated system
were tricked into opening a crafted image file, a remote attacker
could use this flaw to cause GDK-PixBuf to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-8875)

Franco Costantini discovered that the GDK-PixBuf library contained an
out-of-bounds write error when parsing an ico file. If a user or
automated system were tricked into opening a crafted ico file, a
remote attacker could use this flaw to cause GDK-PixBuf to crash,
resulting in a denial of service. This issue only affected Ubuntu
14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-6352).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgdk-pixbuf2.0-0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdk-pixbuf2.0-0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libgdk-pixbuf2.0-0", pkgver:"2.26.1-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libgdk-pixbuf2.0-0", pkgver:"2.30.7-0ubuntu1.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libgdk-pixbuf2.0-0", pkgver:"2.32.2-1ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgdk-pixbuf2.0-0");
}
