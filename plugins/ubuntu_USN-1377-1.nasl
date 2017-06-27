#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1377-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58146);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2010-0541", "CVE-2011-0188", "CVE-2011-1004", "CVE-2011-1005", "CVE-2011-2686", "CVE-2011-2705", "CVE-2011-4815");
  script_bugtraq_id(40895, 46458, 46460, 46966, 49015, 51198);
  script_osvdb_id(65556, 70957, 70958, 71640, 74647, 74841, 78118);
  script_xref(name:"USN", value:"1377-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 / 11.04 / 11.10 : ruby1.8 vulnerabilities (USN-1377-1)");
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
"Drew Yao discovered that the WEBrick HTTP server was vulnerable to
cross-site scripting attacks when displaying error pages. A remote
attacker could use this flaw to run arbitrary web script.
(CVE-2010-0541)

Drew Yao discovered that Ruby's BigDecimal module did not properly
allocate memory on 64-bit platforms. An attacker could use this flaw
to cause a denial of service or possibly execute arbitrary code with
user privileges. (CVE-2011-0188)

Nicholas Jefferson discovered that the FileUtils.remove_entry_secure
method in Ruby did not properly remove non-empty directories. An
attacker could use this flaw to possibly delete arbitrary files.
(CVE-2011-1004)

It was discovered that Ruby incorrectly allowed untainted strings to
be modified in protective safe levels. An attacker could use this flaw
to bypass intended access restrictions. (CVE-2011-1005)

Eric Wong discovered that Ruby does not properly reseed its
pseudorandom number generator when creating child processes. An
attacker could use this flaw to gain knowledge of the random numbers
used in other Ruby child processes. (CVE-2011-2686)

Eric Wong discovered that the SecureRandom module in Ruby did not
properly seed its pseudorandom number generator. An attacker could use
this flaw to gain knowledge of the random numbers used by another Ruby
process with the same process ID number. (CVE-2011-2705)

Alexander Klink and Julian Walde discovered that Ruby computed hash
values without restricting the ability to trigger hash collisions
predictably. A remote attacker could cause a denial of service by
crafting values used in hash tables. (CVE-2011-4815).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libruby1.8 and / or ruby1.8 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libruby1.8", pkgver:"1.8.7.249-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ruby1.8", pkgver:"1.8.7.249-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libruby1.8", pkgver:"1.8.7.299-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"ruby1.8", pkgver:"1.8.7.299-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libruby1.8", pkgver:"1.8.7.302-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"ruby1.8", pkgver:"1.8.7.302-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libruby1.8", pkgver:"1.8.7.352-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"ruby1.8", pkgver:"1.8.7.352-2ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libruby1.8 / ruby1.8");
}
