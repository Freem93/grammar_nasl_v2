#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2255-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76250);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/24 17:29:03 $");

  script_cve_id("CVE-2013-6433", "CVE-2014-0187", "CVE-2014-4167");
  script_bugtraq_id(67012, 67804, 68064);
  script_xref(name:"USN", value:"2255-1");

  script_name(english:"Ubuntu 13.10 / 14.04 LTS : neutron vulnerabilities (USN-2255-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Darragh O'Reilly discovered that the Ubuntu packaging for OpenStack
Neutron did not properly set up its sudo configuration. If a different
flaw was found in OpenStack Neutron, this vulnerability could be used
to escalate privileges. (CVE-2013-6433)

Stephen Ma and Christoph Thiel discovered that the openvswitch-agent
in OpenStack Neutron did not properly perform input validation when
creating security group rules when specifying --remote-ip-prefix. A
remote authenticated attacker could exploit this to prevent
application of additional rules. (CVE-2014-0187)

Thiago Martins discovered that OpenStack Neutron would inappropriately
apply SNAT rules to IPv6 subnets when using the L3-agent. A remote
authenticated attacker could exploit this to prevent floating IPv4
addresses from being attached throughout the cloud. (CVE-2014-4167).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-neutron package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-neutron");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(13\.10|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 13.10 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"13.10", pkgname:"python-neutron", pkgver:"1:2013.2.3-0ubuntu1.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python-neutron", pkgver:"1:2014.1-0ubuntu1.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-neutron");
}
