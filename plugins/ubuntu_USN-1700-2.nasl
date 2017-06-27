# This script was automatically generated from Ubuntu Security
# Notice USN-1700-2.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(64435);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

 script_cve_id("CVE-2012-4530", "CVE-2012-5532");
  script_xref(name:"USN", value:"1700-2");

  script_name(english:"USN-1700-2 : linux-ti-omap4 regression");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"USN-1700-1 fixed vulnerabilities in the Linux kernel. Due to an
unrelated regression inotify/fanotify stopped working after
upgrading. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 A flaw was discovered in the Linux kernel's handling of script
execution when module loading is enabled. A local attacker could
exploit this flaw to cause a leak of kernel stack contents.
(CVE-2012-4530)
 
 Florian Weimer discovered that hypervkvpd, which is distributed in
the Linux kernel, was not correctly validating source addresses of
netlink packets. An untrusted local user can cause a denial of
service by causing hypervkvpd to exit. (CVE-2012-5532)");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1700-2/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/01");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/03");
  script_end_attributes();
    
  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright("Ubuntu Security Notice (C) 2013 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include("ubuntu.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Ubuntu/release")) exit(0, "The host is not running Ubuntu.");
if (!get_kb_item("Host/Debian/dpkg-l")) exit(1, "Could not obtain the list of installed packages.");

flag = 0;

if (ubuntu_check(osver:"12.10", pkgname:"linux-image-3.5.0-218-omap4", pkgver:"3.5.0-218.26")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:ubuntu_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
