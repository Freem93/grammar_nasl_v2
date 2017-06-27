#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-776-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38777);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-1945", "CVE-2008-2004", "CVE-2008-2382", "CVE-2008-4539", "CVE-2008-5714");
  script_bugtraq_id(23731, 32910);
  script_xref(name:"USN", value:"776-2");

  script_name(english:"Ubuntu 8.04 LTS : kvm regression (USN-776-2)");
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
"USN-776-1 fixed vulnerabilities in KVM. Due to an incorrect fix, a
regression was introduced in Ubuntu 8.04 LTS that caused KVM to fail
to boot virtual machines started via libvirt. This update fixes the
problem. We apologize for the inconvenience.

Avi Kivity discovered that KVM did not correctly handle certain disk
formats. A local attacker could attach a malicious partition that
would allow the guest VM to read files on the VM host. (CVE-2008-1945,
CVE-2008-2004)

Alfredo Ortega discovered that KVM's VNC protocol handler
did not correctly validate certain messages. A remote
attacker could send specially crafted VNC messages that
would cause KVM to consume CPU resources, leading to a
denial of service. (CVE-2008-2382)

Jan Niehusmann discovered that KVM's Cirrus VGA
implementation over VNC did not correctly handle certain
bitblt operations. A local attacker could exploit this flaw
to potentially execute arbitrary code on the VM host or
crash KVM, leading to a denial of service. (CVE-2008-4539)

It was discovered that KVM's VNC password checks did not use
the correct length. A remote attacker could exploit this
flaw to cause KVM to crash, leading to a denial of service.
(CVE-2008-5714).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kvm and / or kvm-source packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kvm-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/14");
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
if (! ereg(pattern:"^(8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"kvm", pkgver:"1:62+dfsg-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kvm-source", pkgver:"62+dfsg-0ubuntu8.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kvm / kvm-source");
}
