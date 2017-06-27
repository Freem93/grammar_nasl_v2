#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1294-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57058);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/26 14:05:57 $");

  script_cve_id("CVE-2011-1162", "CVE-2011-2494", "CVE-2011-2942", "CVE-2011-3209", "CVE-2011-3638", "CVE-2011-4081", "CVE-2011-4087", "CVE-2011-4326");
  script_bugtraq_id(50311, 50313, 50314, 50322, 50366, 50751, 50764);
  script_osvdb_id(77684);
  script_xref(name:"USN", value:"1294-1");

  script_name(english:"Ubuntu 10.04 LTS : linux-lts-backport-oneiric vulnerabilities (USN-1294-1)");
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
"Peter Huewe discovered an information leak in the handling of reading
security-related TPM data. A local, unprivileged user could read the
results of a previous TPM command. (CVE-2011-1162)

Vasiliy Kulikov discovered that taskstats did not enforce access
restrictions. A local attacker could exploit this to read certain
information, leading to a loss of privacy. (CVE-2011-2494)

Qianfeng Zhang discovered that the bridge networking interface
incorrectly handled certain network packets. A remote attacker could
exploit this to crash the system, leading to a denial of service.
(CVE-2011-2942)

Yasuaki Ishimatsu discovered a flaw in the kernel's clock
implementation. A local unprivileged attacker could exploit this
causing a denial of service. (CVE-2011-3209)

Zheng Liu discovered a flaw in how the ext4 filesystem splits extents.
A local unprivileged attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-3638)

Scot Doyle discovered that the bridge networking interface incorrectly
handled certain network packets. A remote attacker could exploit this
to crash the system, leading to a denial of service. (CVE-2011-4087)

A bug was found in the way headroom check was performed in
udp6_ufo_fragment() function. A remote attacker could use this flaw to
crash the system. (CVE-2011-4326).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/09");
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
if (! ereg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-3.0.0-13-generic", pkgver:"3.0.0-13.22~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-3.0.0-13-generic-pae", pkgver:"3.0.0-13.22~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-3.0.0-13-server", pkgver:"3.0.0-13.22~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-3.0.0-13-virtual", pkgver:"3.0.0-13.22~lucid1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.0-generic / linux-image-3.0-generic-pae / etc");
}
