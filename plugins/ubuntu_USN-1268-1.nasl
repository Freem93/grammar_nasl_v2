#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1268-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56911);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/26 14:05:57 $");

  script_cve_id("CVE-2011-1585", "CVE-2011-1767", "CVE-2011-1768", "CVE-2011-2491", "CVE-2011-2496", "CVE-2011-2525", "CVE-2011-3209");
  script_bugtraq_id(47852, 47853, 48641, 50311);
  script_osvdb_id(74651, 74652, 74657, 74659, 74660, 74661, 77355);
  script_xref(name:"USN", value:"1268-1");

  script_name(english:"Ubuntu 8.04 LTS : linux vulnerabilities (USN-1268-1)");
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
"It was discovered that CIFS incorrectly handled authentication. When a
user had a CIFS share mounted that required authentication, a local
user could mount the same share without knowing the correct password.
(CVE-2011-1585)

It was discovered that the GRE protocol incorrectly handled netns
initialization. A remote attacker could send a packet while the ip_gre
module was loading, and crash the system, leading to a denial of
service. (CVE-2011-1767)

It was discovered that the IP/IP protocol incorrectly handled netns
initialization. A remote attacker could send a packet while the ipip
module was loading, and crash the system, leading to a denial of
service. (CVE-2011-1768)

Vasily Averin discovered that the NFS Lock Manager (NLM) incorrectly
handled unlock requests. A local attacker could exploit this to cause
a denial of service. (CVE-2011-2491)

Robert Swiecki discovered that mapping extensions were incorrectly
handled. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-2496)

Ben Pfaff discovered that Classless Queuing Disciplines (qdiscs) were
being incorrectly handled. A local attacker could exploit this to
crash the system, leading to a denial of service. (CVE-2011-2525)

Yasuaki Ishimatsu discovered a flaw in the kernel's clock
implementation. A local unprivileged attacker could exploit this
causing a denial of service. (CVE-2011-3209).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-30-386", pkgver:"2.6.24-30.96")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-30-generic", pkgver:"2.6.24-30.96")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-30-lpia", pkgver:"2.6.24-30.96")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-30-lpiacompat", pkgver:"2.6.24-30.96")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-30-openvz", pkgver:"2.6.24-30.96")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-30-rt", pkgver:"2.6.24-30.96")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-30-server", pkgver:"2.6.24-30.96")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-30-virtual", pkgver:"2.6.24-30.96")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-30-xen", pkgver:"2.6.24-30.96")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-386 / linux-image-2.6-generic / etc");
}
