#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1303-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57304);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/12/27 15:24:34 $");

  script_cve_id("CVE-2011-1162", "CVE-2011-4077", "CVE-2011-4081", "CVE-2011-4132", "CVE-2011-4326", "CVE-2011-4330");
  script_bugtraq_id(50764);
  script_xref(name:"USN", value:"1303-1");

  script_name(english:"Ubuntu 10.10 : linux-mvl-dove vulnerabilities (USN-1303-1)");
  script_summary(english:"Checks dpkg output for updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Peter Huewe discovered an information leak in the handling of reading
security-related TPM data. A local, unprivileged user could read the
results of a previous TPM command. (CVE-2011-1162)

A bug was discovered in the XFS filesystem's handling of pathnames. A
local attacker could exploit this to crash the system, leading to a
denial of service, or gain root privileges. (CVE-2011-4077)

Nick Bowler discovered the kernel GHASH message digest algorithm
incorrectly handled error conditions. A local attacker could exploit
this to cause a kernel oops. (CVE-2011-4081)

A flaw was found in the Journaling Block Device (JBD). A local
attacker able to mount ext3 or ext4 file systems could exploit this to
crash the system, leading to a denial of service. (CVE-2011-4132)

A bug was found in the way headroom check was performed in
udp6_ufo_fragment() function. A remote attacker could use this flaw to
crash the system. (CVE-2011-4326)

Clement Lecigne discovered a bug in the HFS file system bounds
checking. When a malformed HFS file system is mounted a local user
could crash the system or gain root privileges. (CVE-2011-4330)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected linux-image-2.6.32-421-dove package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2013 Canonical, Inc. / NASL script (C) 2011-2013 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.32-421-dove", pkgver:"2.6.32-421.39")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
