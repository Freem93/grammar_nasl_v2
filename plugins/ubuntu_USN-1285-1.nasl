#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1285-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56978);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/26 14:05:57 $");

  script_cve_id("CVE-2011-2183", "CVE-2011-2491", "CVE-2011-2494", "CVE-2011-2495", "CVE-2011-2517", "CVE-2011-2905", "CVE-2011-2909");
  script_bugtraq_id(48101, 48538, 49140, 49141, 49408, 49411, 50314);
  script_osvdb_id(74634, 74658, 74660, 74676, 74680, 74882, 76796);
  script_xref(name:"USN", value:"1285-1");

  script_name(english:"Ubuntu 11.04 : linux vulnerabilities (USN-1285-1)");
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
"Andrea Righi discovered a race condition in the KSM memory merging
support. If KSM was being used, a local attacker could exploit this to
crash the system, leading to a denial of service. (CVE-2011-2183)

Vasily Averin discovered that the NFS Lock Manager (NLM) incorrectly
handled unlock requests. A local attacker could exploit this to cause
a denial of service. (CVE-2011-2491)

Vasiliy Kulikov discovered that taskstats did not enforce access
restrictions. A local attacker could exploit this to read certain
information, leading to a loss of privacy. (CVE-2011-2494)

Vasiliy Kulikov discovered that /proc/PID/io did not enforce access
restrictions. A local attacker could exploit this to read certain
information, leading to a loss of privacy. (CVE-2011-2495)

It was discovered that the wireless stack incorrectly verified SSID
lengths. A local attacker could exploit this to cause a denial of
service or gain root privileges. (CVE-2011-2517)

Christian Ohm discovered that the perf command looks for configuration
files in the current directory. If a privileged user were tricked into
running perf in a directory containing a malicious configuration file,
an attacker could run arbitrary commands and possibly gain privileges.
(CVE-2011-2905)

Vasiliy Kulikov discovered that the Comedi driver did not correctly
clear memory. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2011-2909).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/30");
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
if (! ereg(pattern:"^(11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-13-generic", pkgver:"2.6.38-13.52")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-13-generic-pae", pkgver:"2.6.38-13.52")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-13-server", pkgver:"2.6.38-13.52")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-13-versatile", pkgver:"2.6.38-13.52")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"linux-image-2.6.38-13-virtual", pkgver:"2.6.38-13.52")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-generic / linux-image-2.6-generic-pae / etc");
}
