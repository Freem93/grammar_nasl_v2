# This script was automatically generated from Ubuntu Security
# Notice USN-1271-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(56913);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

 script_cve_id("CVE-2011-1585", "CVE-2011-1767", "CVE-2011-1768", "CVE-2011-2491");
  script_xref(name:"USN", value:"1271-1");

  script_name(english:"USN-1271-1 : linux-fsl-imx51 vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"It was discovered that CIFS incorrectly handled authentication. When
a user had a CIFS share mounted that required authentication, a local
user could mount the same share without knowing the correct password.
(CVE-2011-1585)

It was discovered that the GRE protocol incorrectly handled netns
initialization. A remote attacker could send a packet while the
ip_gre module was loading, and crash the system, leading to a denial
of service. (CVE-2011-1767)

It was discovered that the IP/IP protocol incorrectly handled netns
initialization. A remote attacker could send a packet while the ipip
module was loading, and crash the system, leading to a denial of
service. (CVE-2011-1768)

Vasily Averin discovered that the NFS Lock Manager (NLM) incorrectly
handled unlock requests. A local attacker could exploit this to cause
a denial of service. (CVE-2011-2491)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1271-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/21");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/22");
  script_end_attributes();
    
  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright("Ubuntu Security Notice (C) 2011-2012 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include("ubuntu.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Ubuntu/release")) exit(0, "The host is not running Ubuntu.");
if (!get_kb_item("Host/Debian/dpkg-l")) exit(1, "Could not obtain the list of installed packages.");

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.31-612-imx51", pkgver:"2.6.31-612.30")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:ubuntu_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
