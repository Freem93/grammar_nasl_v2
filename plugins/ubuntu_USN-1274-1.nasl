#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1274-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56916);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/01/27 00:51:26 $");

  script_cve_id("CVE-2011-2491", "CVE-2011-2496", "CVE-2011-2517", "CVE-2011-2525");
  script_bugtraq_id(48538, 48641);
  script_xref(name:"USN", value:"1274-1");

  script_name(english:"Ubuntu 10.10 : linux-mvl-dove vulnerabilities (USN-1274-1)");
  script_summary(english:"Checks dpkg output for updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vasily Averin discovered that the NFS Lock Manager (NLM) incorrectly
handled unlock requests. A local attacker could exploit this to cause
a denial of service. (CVE-2011-2491)

Robert Swiecki discovered that mapping extensions were incorrectly
handled. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2011-2496)

It was discovered that the wireless stack incorrectly verified SSID
lengths. A local attacker could exploit this to cause a denial of
service or gain root privileges. (CVE-2011-2517)

Ben Pfaff discovered that Classless Queuing Disciplines (qdiscs) were
being incorrectly handled. A local attacker could exploit this to
crash the system, leading to a denial of service. (CVE-2011-2525)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected linux-image-2.6.32-420-dove package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2013 Canonical, Inc. / NASL script (C) 2011-2014 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}



include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/Ubuntu/release") ) audit(AUDIT_OS_NOT, "Ubuntu");
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.32-420-dove", pkgver:"2.6.32-420.38")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
