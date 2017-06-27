#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1907-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68926);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/25 16:27:06 $");

  script_cve_id("CVE-2013-1500", "CVE-2013-1571", "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2446", "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2449", "CVE-2013-2450", "CVE-2013-2451", "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2454", "CVE-2013-2455", "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2458", "CVE-2013-2459", "CVE-2013-2460", "CVE-2013-2461", "CVE-2013-2463", "CVE-2013-2465", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473");
  script_osvdb_id(94335, 94336, 94337, 94339, 94340, 94341, 94346, 94347, 94348, 94350, 94352, 94353, 94354, 94355, 94356, 94357, 94358, 94362, 94363, 94364, 94365, 94366, 94367, 94368, 94369, 94370, 94371, 94372, 94373, 94374);
  script_xref(name:"USN", value:"1907-2");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.04 : icedtea-web update (USN-1907-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-1907-1 fixed vulnerabilities in OpenJDK 7. Due to upstream
changes, IcedTea Web needed an update to work with the new OpenJDK 7.

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit
these to expose sensitive data over the network. (CVE-2013-1500,
CVE-2013-2454, CVE-2013-2458)

A vulnerability was discovered in the OpenJDK Javadoc
related to data integrity. (CVE-2013-1571)

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure and availability. An attacker could
exploit this to cause a denial of service or expose
sensitive data over the network. (CVE-2013-2407)

Several vulnerabilities were discovered in the OpenJDK JRE
related to information disclosure. An attacker could exploit
these to expose sensitive data over the network.
(CVE-2013-2412, CVE-2013-2443, CVE-2013-2446, CVE-2013-2447,
CVE-2013-2449, CVE-2013-2452, CVE-2013-2456)

Several vulnerabilities were discovered in the OpenJDK JRE
related to availability. An attacker could exploit these to
cause a denial of service. (CVE-2013-2444, CVE-2013-2445,
CVE-2013-2450)

Several vulnerabilities were discovered in the OpenJDK JRE
related to information disclosure, data integrity and
availability. An attacker could exploit these to cause a
denial of service or expose sensitive data over the network.
(CVE-2013-2448, CVE-2013-2451, CVE-2013-2459, CVE-2013-2460,
CVE-2013-2461, CVE-2013-2463, CVE-2013-2465, CVE-2013-2469,
CVE-2013-2470, CVE-2013-2471, CVE-2013-2472, CVE-2013-2473)

Several vulnerabilities were discovered in the OpenJDK JRE
related to data integrity. (CVE-2013-2453, CVE-2013-2455,
CVE-2013-2457).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icedtea-netx package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:icedtea-netx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|12\.10|13\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"icedtea-netx", pkgver:"1.2.3-0ubuntu0.12.04.3")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"icedtea-netx", pkgver:"1.3.2-1ubuntu0.12.10.2")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"icedtea-netx", pkgver:"1.3.2-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-netx");
}
