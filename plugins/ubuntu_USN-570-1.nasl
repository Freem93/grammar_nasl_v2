#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-570-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30018);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_cve_id("CVE-2008-0171", "CVE-2008-0172");
  script_osvdb_id(42790, 42791);
  script_xref(name:"USN", value:"570-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : boost vulnerabilities (USN-570-1)");
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
"Will Drewry and Tavis Ormandy discovered that the boost library did
not properly perform input validation on regular expressions. An
attacker could send a specially crafted regular expression to an
application linked against boost and cause a denial of service via
application crash.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-date-time-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-date-time1.33.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-date-time1.34.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-filesystem-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-filesystem1.33.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-filesystem1.34.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-graph-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-graph1.33.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-graph1.34.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-iostreams-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-iostreams1.33.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-iostreams1.34.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-program-options-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-program-options1.33.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-program-options1.34.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-python-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-python1.33.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-python1.34.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-regex-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-regex1.33.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-regex1.34.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-serialization-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-serialization1.34.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-signals-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-signals1.33.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-signals1.34.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-test-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-test1.33.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-test1.34.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-thread-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-thread1.33.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-thread1.34.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-wave-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libboost-wave1.34.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pyste");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"bcp", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-date-time-dev", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-date-time1.33.1", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-dbg", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-dev", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-doc", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-filesystem-dev", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-filesystem1.33.1", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-graph-dev", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-graph1.33.1", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-iostreams-dev", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-iostreams1.33.1", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-program-options-dev", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-program-options1.33.1", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-python-dev", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-python1.33.1", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-regex-dev", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-regex1.33.1", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-serialization-dev", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-signals-dev", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-signals1.33.1", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-test-dev", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-test1.33.1", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-thread-dev", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-thread1.33.1", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libboost-wave-dev", pkgver:"1.33.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"bcp", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-date-time-dev", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-date-time1.33.1", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-dbg", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-dev", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-doc", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-filesystem-dev", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-filesystem1.33.1", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-graph-dev", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-graph1.33.1", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-iostreams-dev", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-iostreams1.33.1", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-program-options-dev", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-program-options1.33.1", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-python-dev", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-python1.33.1", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-regex-dev", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-regex1.33.1", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-serialization-dev", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-signals-dev", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-signals1.33.1", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-test-dev", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-test1.33.1", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-thread-dev", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-thread1.33.1", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libboost-wave-dev", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"pyste", pkgver:"1.33.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"bcp", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-date-time-dev", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-date-time1.33.1", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-dbg", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-dev", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-doc", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-filesystem-dev", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-filesystem1.33.1", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-graph-dev", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-graph1.33.1", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-iostreams-dev", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-iostreams1.33.1", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-program-options-dev", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-program-options1.33.1", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-python-dev", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-python1.33.1", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-regex-dev", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-regex1.33.1", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-serialization-dev", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-signals-dev", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-signals1.33.1", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-test-dev", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-test1.33.1", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-thread-dev", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-thread1.33.1", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libboost-wave-dev", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"pyste", pkgver:"1.33.1-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"bcp", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-date-time-dev", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-date-time1.34.1", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-dbg", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-dev", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-doc", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-filesystem-dev", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-filesystem1.34.1", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-graph-dev", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-graph1.34.1", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-iostreams-dev", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-iostreams1.34.1", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-program-options-dev", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-program-options1.34.1", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-python-dev", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-python1.34.1", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-regex-dev", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-regex1.34.1", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-serialization-dev", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-serialization1.34.1", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-signals-dev", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-signals1.34.1", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-test-dev", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-test1.34.1", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-thread-dev", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-thread1.34.1", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-wave-dev", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libboost-wave1.34.1", pkgver:"1.34.1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"pyste", pkgver:"1.34.1-2ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bcp / libboost-date-time-dev / libboost-date-time1.33.1 / etc");
}
