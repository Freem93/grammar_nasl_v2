#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2867-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87888);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2011-4600", "CVE-2014-8136", "CVE-2015-0236", "CVE-2015-5247", "CVE-2015-5313");
  script_osvdb_id(78232, 116144, 117504, 127452, 131656);
  script_xref(name:"USN", value:"2867-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 / 15.10 : libvirt vulnerabilities (USN-2867-1)");
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
"It was discovered that libvirt incorrectly handled the firewall rules
on bridge networks when the daemon was restarted. This could result in
an unintended firewall configuration. This issue only applied to
Ubuntu 12.04 LTS. (CVE-2011-4600)

Peter Krempa discovered that libvirt incorrectly handled locking when
certain ACL checks failed. A local attacker could use this issue to
cause libvirt to stop responding, resulting in a denial of service.
This issue only applied to Ubuntu 14.04 LTS. (CVE-2014-8136)

Luyao Huang discovered that libvirt incorrectly handled VNC passwords
in shapshot and image files. A remote authenticated user could use
this issue to possibly obtain VNC passwords. This issue only affected
Ubuntu 14.04 LTS. (CVE-2015-0236)

Han Han discovered that libvirt incorrectly handled volume creation
failure when used with NFS. A remote authenticated user could use this
issue to cause libvirt to crash, resulting in a denial of service.
This issue only applied to Ubuntu 15.10. (CVE-2015-5247)

Ossi Herrala and Joonas Kuorilehto discovered that libvirt incorrectly
performed storage pool name validation. A remote authenticated user
could use this issue to bypass ACLs and gain access to unintended
files. This issue only applied to Ubuntu 14.04 LTS, Ubuntu 15.04 and
Ubuntu 15.10. (CVE-2015-5313).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt-bin and / or libvirt0 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/13");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libvirt-bin", pkgver:"0.9.8-2ubuntu17.23")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libvirt0", pkgver:"0.9.8-2ubuntu17.23")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libvirt-bin", pkgver:"1.2.2-0ubuntu13.1.16")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libvirt0", pkgver:"1.2.2-0ubuntu13.1.16")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libvirt-bin", pkgver:"1.2.12-0ubuntu14.4")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"libvirt0", pkgver:"1.2.12-0ubuntu14.4")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libvirt-bin", pkgver:"1.2.16-2ubuntu11.15.10.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libvirt0", pkgver:"1.2.16-2ubuntu11.15.10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt-bin / libvirt0");
}
