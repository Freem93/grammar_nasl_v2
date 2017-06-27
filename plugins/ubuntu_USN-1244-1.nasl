# This script was automatically generated from Ubuntu Security
# Notice USN-1244-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(56643);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

  script_cve_id("CVE-2010-3873", "CVE-2011-2183", "CVE-2011-2491", "CVE-2011-2494", "CVE-2011-2495", "CVE-2011-2517", "CVE-2011-2695", "CVE-2011-2905", "CVE-2011-2909", "CVE-2011-3363");
  script_xref(name:"USN", value:"1244-1");

  script_name(english:"USN-1244-1 : linux-ti-omap4 vulnerabilities");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Dan Rosenberg discovered that the Linux kernel X.25 implementation
incorrectly parsed facilities. A remote attacker could exploit this
to crash the kernel, leading to a denial of service. (CVE-2010-3873)

Andrea Righi discovered a race condition in the KSM memory merging
support. If KSM was being used, a local attacker could exploit this
to crash the system, leading to a denial of service. (CVE-2011-2183)

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

It was discovered that the EXT4 filesystem contained multiple
off-by-one flaws. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2011-2695)

Christian Ohm discovered that the perf command looks for
configuration files in the current directory. If a privileged user
were tricked into running perf in a directory containing a malicious
configuration file, an attacker could run arbitrary commands and
possibly gain privileges. (CVE-2011-2905)

Vasiliy Kulikov discovered that the Comedi driver did not correctly
clear memory. A local attacker could exploit this to read kernel
stack memory, leading to a loss of privacy. (CVE-2011-2909)

Yogesh Sharma discovered that CIFS did not correctly handle UNCs that
had no prefixpaths. A local attacker with access to a CIFS partition
could exploit this to crash the system, leading to a denial of
service. (CVE-2011-3363)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1244-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/25");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/26");
  script_end_attributes();
    
  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright("Ubuntu Security Notice (C) 2011 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include("ubuntu.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Ubuntu/release")) exit(0, "The host is not running Ubuntu.");
if (!get_kb_item("Host/Debian/dpkg-l")) exit(1, "Could not obtain the list of installed packages.");

flag = 0;

if (ubuntu_check(osver:"10.10", pkgname:"linux-image-2.6.35-903-omap4", pkgver:"2.6.35-903.26")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
