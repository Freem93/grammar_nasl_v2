#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3087-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93715);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-6302", "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-6306");
  script_osvdb_id(143021);
  script_xref(name:"USN", value:"3087-2");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS : openssl regression (USN-3087-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-3087-1 fixed vulnerabilities in OpenSSL. The fix for CVE-2016-2182
was incomplete and caused a regression when parsing certificates. This
update fixes the problem.

We apologize for the inconvenience.

Shi Lei discovered that OpenSSL incorrectly handled the OCSP Status
Request extension. A remote attacker could possibly use this issue to
cause memory consumption, resulting in a denial of service.
(CVE-2016-6304)

Guido Vranken discovered that OpenSSL used undefined
behaviour when performing pointer arithmetic. A remote
attacker could possibly use this issue to cause OpenSSL to
crash, resulting in a denial of service. This issue has only
been addressed in Ubuntu 16.04 LTS in this update.
(CVE-2016-2177)

Cesar Pereida, Billy Brumley, and Yuval Yarom discovered
that OpenSSL did not properly use constant-time operations
when performing DSA signing. A remote attacker could
possibly use this issue to perform a cache-timing attack and
recover private DSA keys. (CVE-2016-2178)

Quan Luo discovered that OpenSSL did not properly restrict
the lifetime of queue entries in the DTLS implementation. A
remote attacker could possibly use this issue to consume
memory, resulting in a denial of service. (CVE-2016-2179)

Shi Lei discovered that OpenSSL incorrectly handled memory
in the TS_OBJ_print_bio() function. A remote attacker could
possibly use this issue to cause a denial of service.
(CVE-2016-2180)

It was discovered that the OpenSSL incorrectly handled the
DTLS anti-replay feature. A remote attacker could possibly
use this issue to cause a denial of service. (CVE-2016-2181)

Shi Lei discovered that OpenSSL incorrectly validated
division results. A remote attacker could possibly use this
issue to cause a denial of service. (CVE-2016-2182)

Karthik Bhargavan and Gaetan Leurent discovered that the DES
and Triple DES ciphers were vulnerable to birthday attacks.
A remote attacker could possibly use this flaw to obtain
clear text data from long encrypted sessions. This update
moves DES from the HIGH cipher list to MEDIUM.
(CVE-2016-2183)

Shi Lei discovered that OpenSSL incorrectly handled certain
ticket lengths. A remote attacker could use this issue to
cause a denial of service. (CVE-2016-6302)

Shi Lei discovered that OpenSSL incorrectly handled memory
in the MDC2_Update() function. A remote attacker could
possibly use this issue to cause a denial of service.
(CVE-2016-6303)

Shi Lei discovered that OpenSSL incorrectly performed
certain message length checks. A remote attacker could
possibly use this issue to cause a denial of service.
(CVE-2016-6306).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libssl1.0.0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libssl1.0.0", pkgver:"1.0.1-4ubuntu5.38")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libssl1.0.0", pkgver:"1.0.1f-1ubuntu2.21")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libssl1.0.0", pkgver:"1.0.2g-1ubuntu4.5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssl1.0.0");
}
