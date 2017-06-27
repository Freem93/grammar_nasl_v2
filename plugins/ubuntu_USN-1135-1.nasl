#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1135-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55096);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/27 14:13:24 $");

  script_cve_id("CVE-2011-1407");
  script_bugtraq_id(47836);
  script_osvdb_id(72642);
  script_xref(name:"USN", value:"1135-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 / 11.04 : exim4 vulnerability (USN-1135-1)");
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
"It was discovered that the Exim daemon did not correctly handle
certain DKIM identities. A remote attacker could send specially
crafted email to run arbitrary code as the Exim user.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected exim4-daemon-custom, exim4-daemon-heavy and / or
exim4-daemon-light packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-heavy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-light");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/13");
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
if (! ereg(pattern:"^(10\.04|10\.10|11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10 / 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"exim4-daemon-custom", pkgver:"4.71-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"exim4-daemon-heavy", pkgver:"4.71-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"exim4-daemon-light", pkgver:"4.71-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"exim4-daemon-custom", pkgver:"4.72-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"exim4-daemon-heavy", pkgver:"4.72-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"exim4-daemon-light", pkgver:"4.72-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"exim4-daemon-custom", pkgver:"4.74-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"exim4-daemon-heavy", pkgver:"4.74-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"exim4-daemon-light", pkgver:"4.74-1ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim4-daemon-custom / exim4-daemon-heavy / exim4-daemon-light");
}
