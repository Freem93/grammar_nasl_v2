#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2469-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81177);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/24 17:37:07 $");

  script_cve_id("CVE-2015-0219", "CVE-2015-0220", "CVE-2015-0221", "CVE-2015-0222");
  script_bugtraq_id(72078, 72079, 72080, 72081);
  script_osvdb_id(117065, 117066, 117067, 117068);
  script_xref(name:"USN", value:"2469-2");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS : python-django regression (USN-2469-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2469-1 fixed vulnerabilities in Django. The security fix for
CVE-2015-0221 introduced a regression on Ubuntu 10.04 LTS and Ubuntu
12.04 LTS when serving static content through GZipMiddleware. This
update fixes the problem.

We apologize for the inconvenience.

Jedediah Smith discovered that Django incorrectly handled underscores
in WSGI headers. A remote attacker could possibly use this issue to
spoof headers in certain environments. (CVE-2015-0219)

Mikko Ohtamaa discovered that Django incorrectly handled
user-supplied redirect URLs. A remote attacker could
possibly use this issue to perform a cross-site scripting
attack. (CVE-2015-0220)

Alex Gaynor discovered that Django incorrectly handled
reading files in django.views.static.serve(). A remote
attacker could possibly use this issue to cause Django to
consume resources, resulting in a denial of service.
(CVE-2015-0221)

Keryn Knight discovered that Django incorrectly handled
forms with ModelMultipleChoiceField. A remote attacker could
possibly use this issue to cause a large number of SQL
queries, resulting in a database denial of service. This
issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10.
(CVE-2015-0222).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-django package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"python-django", pkgver:"1.1.1-2ubuntu1.16")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python-django", pkgver:"1.3.1-4ubuntu1.15")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-django");
}
