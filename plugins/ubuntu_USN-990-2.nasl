#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-990-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49644);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2009-3555");
  script_bugtraq_id(36935);
  script_osvdb_id(59969);
  script_xref(name:"USN", value:"990-2");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.04 / 9.10 / 10.04 LTS : apache2 vulnerability (USN-990-2)");
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
"USN-860-1 introduced a partial workaround to Apache that disabled
client initiated TLS renegotiation in order to mitigate CVE-2009-3555.
USN-990-1 introduced the new RFC5746 renegotiation extension in
openssl, and completely resolves the issue.

After updating openssl, an Apache server will allow both patched and
unpatched web browsers to connect, but unpatched browsers will not be
able to renegotiate. This update introduces the new
SSLInsecureRenegotiation directive for Apache that may be used to
re-enable insecure renegotiations with unpatched web browsers. For
more information, please refer to:
http://httpd.apache.org/docs/2.2/mod/mod_ssl.html#sslinsecurerenegotia
tion

Marsh Ray and Steve Dispensa discovered a flaw in the TLS and SSLv3
protocols. If an attacker could perform a man in the middle attack at
the start of a TLS connection, the attacker could inject arbitrary
content at the beginning of the user's session. This update adds
backported support for the new RFC5746 renegotiation extension and
will use it when both the client and the server support it.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-perchild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-prefork-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-threaded-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2.2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2.2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapr0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"apache2", pkgver:"2.0.55-4ubuntu2.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-common", pkgver:"2.0.55-4ubuntu2.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-doc", pkgver:"2.0.55-4ubuntu2.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-mpm-perchild", pkgver:"2.0.55-4ubuntu2.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-mpm-prefork", pkgver:"2.0.55-4ubuntu2.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-mpm-worker", pkgver:"2.0.55-4ubuntu2.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-prefork-dev", pkgver:"2.0.55-4ubuntu2.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-threaded-dev", pkgver:"2.0.55-4ubuntu2.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-utils", pkgver:"2.0.55-4ubuntu2.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libapr0", pkgver:"2.0.55-4ubuntu2.11")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libapr0-dev", pkgver:"2.0.55-4ubuntu2.11")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2", pkgver:"2.2.8-1ubuntu0.18")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-doc", pkgver:"2.2.8-1ubuntu0.18")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-mpm-event", pkgver:"2.2.8-1ubuntu0.18")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-mpm-perchild", pkgver:"2.2.8-1ubuntu0.18")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-mpm-prefork", pkgver:"2.2.8-1ubuntu0.18")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-mpm-worker", pkgver:"2.2.8-1ubuntu0.18")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-prefork-dev", pkgver:"2.2.8-1ubuntu0.18")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-src", pkgver:"2.2.8-1ubuntu0.18")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-threaded-dev", pkgver:"2.2.8-1ubuntu0.18")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2-utils", pkgver:"2.2.8-1ubuntu0.18")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"apache2.2-common", pkgver:"2.2.8-1ubuntu0.18")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2", pkgver:"2.2.11-2ubuntu2.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-doc", pkgver:"2.2.11-2ubuntu2.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-mpm-event", pkgver:"2.2.11-2ubuntu2.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-mpm-prefork", pkgver:"2.2.11-2ubuntu2.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-mpm-worker", pkgver:"2.2.11-2ubuntu2.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-prefork-dev", pkgver:"2.2.11-2ubuntu2.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-src", pkgver:"2.2.11-2ubuntu2.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-suexec", pkgver:"2.2.11-2ubuntu2.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-suexec-custom", pkgver:"2.2.11-2ubuntu2.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-threaded-dev", pkgver:"2.2.11-2ubuntu2.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2-utils", pkgver:"2.2.11-2ubuntu2.7")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"apache2.2-common", pkgver:"2.2.11-2ubuntu2.7")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apache2", pkgver:"2.2.12-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apache2-doc", pkgver:"2.2.12-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apache2-mpm-event", pkgver:"2.2.12-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apache2-mpm-itk", pkgver:"2.2.12-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apache2-mpm-prefork", pkgver:"2.2.12-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apache2-mpm-worker", pkgver:"2.2.12-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apache2-prefork-dev", pkgver:"2.2.12-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apache2-suexec", pkgver:"2.2.12-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apache2-suexec-custom", pkgver:"2.2.12-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apache2-threaded-dev", pkgver:"2.2.12-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apache2-utils", pkgver:"2.2.12-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apache2.2-bin", pkgver:"2.2.12-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"apache2.2-common", pkgver:"2.2.12-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2", pkgver:"2.2.14-5ubuntu8.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2-doc", pkgver:"2.2.14-5ubuntu8.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2-mpm-event", pkgver:"2.2.14-5ubuntu8.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2-mpm-itk", pkgver:"2.2.14-5ubuntu8.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2-mpm-prefork", pkgver:"2.2.14-5ubuntu8.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2-mpm-worker", pkgver:"2.2.14-5ubuntu8.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2-prefork-dev", pkgver:"2.2.14-5ubuntu8.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2-suexec", pkgver:"2.2.14-5ubuntu8.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2-suexec-custom", pkgver:"2.2.14-5ubuntu8.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2-threaded-dev", pkgver:"2.2.14-5ubuntu8.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2-utils", pkgver:"2.2.14-5ubuntu8.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2.2-bin", pkgver:"2.2.14-5ubuntu8.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"apache2.2-common", pkgver:"2.2.14-5ubuntu8.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-common / apache2-doc / apache2-mpm-event / etc");
}
