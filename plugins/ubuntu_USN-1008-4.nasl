#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1008-4. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50524);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2010-2237", "CVE-2010-2238", "CVE-2010-2239", "CVE-2010-2242");
  script_xref(name:"USN", value:"1008-4");

  script_name(english:"Ubuntu 10.04 LTS : libvirt regression (USN-1008-4)");
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
"USN-1008-1 fixed vulnerabilities in libvirt. The upstream fixes for
CVE-2010-2238 changed the behavior of libvirt such that the domain XML
could not specify 'host_device' as the qemu sub-type. While libvirt
0.8.3 and later will longer support specifying this sub-type, this
update restores the old behavior on Ubuntu 10.04 LTS.

We apologize for the inconvenience.

It was discovered that libvirt would probe disk backing stores without
consulting the defined format for the disk. A privileged attacker in
the guest could exploit this to read arbitrary files on the host. This
issue only affected Ubuntu 10.04 LTS. By default, guests are confined
by an AppArmor profile which provided partial protection against this
flaw. (CVE-2010-2237, CVE-2010-2238)

It was discovered that libvirt would create new VMs without
setting a backing store format. A privileged attacker in the
guest could exploit this to read arbitrary files on the
host. This issue did not affect Ubuntu 8.04 LTS. In Ubuntu
9.10 and later guests are confined by an AppArmor profile
which provided partial protection against this flaw.
(CVE-2010-2239)

Jeremy Nickurak discovered that libvirt created iptables
rules with too lenient mappings of source ports. A
privileged attacker in the guest could bypass intended
restrictions to access privileged resources on the host.
(CVE-2010-2242).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvirt0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libvirt-bin", pkgver:"0.7.5-5ubuntu27.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libvirt-dev", pkgver:"0.7.5-5ubuntu27.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libvirt-doc", pkgver:"0.7.5-5ubuntu27.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libvirt0", pkgver:"0.7.5-5ubuntu27.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libvirt0-dbg", pkgver:"0.7.5-5ubuntu27.7")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"python-libvirt", pkgver:"0.7.5-5ubuntu27.7")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt-bin / libvirt-dev / libvirt-doc / libvirt0 / libvirt0-dbg / etc");
}
