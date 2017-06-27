# This script was automatically generated from Ubuntu Security
# Notice USN-1599-1.  It is released under the Nessus Script 
# Licence.
#
# Ubuntu Security Notices are (C) Canonical, Inc.
# See http://www.ubuntu.com/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(62475);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

 script_cve_id("CVE-2012-3520");
  script_xref(name:"USN", value:"1599-1");

  script_name(english:"USN-1599-1 : linux-ti-omap4 vulnerability");
  script_summary(english:"Checks dpkg output for updated package(s)");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Ubuntu host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Pablo Neira Ayuso discovered a flaw in the credentials of netlink
messages. An unprivileged local attacker could exploit this by
getting a netlink based service, that relies on netlink credentials,
to perform privileged actions.");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-1599-1/");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");
  script_end_attributes();
    
  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright("Ubuntu Security Notice (C) 2012 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include("ubuntu.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Ubuntu/release")) exit(0, "The host is not running Ubuntu.");
if (!get_kb_item("Host/Debian/dpkg-l")) exit(1, "Could not obtain the list of installed packages.");

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-1420-omap4", pkgver:"3.2.0-1420.27")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:ubuntu_report_get());
  else security_note(0);
  exit(0);
}
else exit(0, "The host is not affected.");
