#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-224-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20767);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2005-0468", "CVE-2005-0469", "CVE-2005-1174", "CVE-2005-1175", "CVE-2005-1689");
  script_xref(name:"USN", value:"224-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : krb4, krb5 vulnerabilities (USN-224-1)");
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
"Gael Delalleau discovered a buffer overflow in the env_opt_add()
function of the Kerberos 4 and 5 telnet clients. By sending specially
crafted replies, a malicious telnet server could exploit this to
execute arbitrary code with the privileges of the user running the
telnet client. (CVE-2005-0468)

Gael Delalleau discovered a buffer overflow in the handling of the
LINEMODE suboptions in the telnet clients of Kerberos 4 and 5. By
sending a specially constructed reply containing a large number of SLC
(Set Local Character) commands, a remote attacker (i. e. a malicious
telnet server) could execute arbitrary commands with the privileges of
the user running the telnet client. (CVE-2005-0469)

Daniel Wachdorf discovered two remote vulnerabilities in the Key
Distribution Center of Kerberos 5 (krb5-kdc). By sending certain TCP
connection requests, a remote attacker could trigger a double-freeing
of memory, which led to memory corruption and a crash of the KDC
server. (CVE-2005-1174). Under rare circumstances the same type of TCP
connection requests could also trigger a buffer overflow that could be
exploited to run arbitrary code with the privileges of the KDC server.
(CVE-2005-1175)

Magnus Hagander discovered that the krb5_recvauth() function attempted
to free previously freed memory in some situations. A remote attacker
could possibly exploit this to run arbitrary code with the privileges
of the program that called this function. Most imporantly, this
affects the following daemons: kpropd (from the krb5-kdc package),
klogind, and kshd (both from the krb5-rsh-server package).
(CVE-2005-1689)

Please note that these packages are not officially supported by Ubuntu
(they are in the 'universe' component of the archive).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kerberos4kth-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kerberos4kth-clients-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kerberos4kth-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kerberos4kth-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kerberos4kth-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kerberos4kth-kip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kerberos4kth-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kerberos4kth-servers-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kerberos4kth-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kerberos4kth-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kerberos4kth-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kerberos4kth1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-ftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-rsh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-telnetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm1-kerberos4kth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkafs0-kerberos4kth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb-1-kerberos4kth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb-1-kerberos4kth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkthacl1-kerberos4kth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libotp0-kerberos4kth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroken16-kerberos4kth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsl0-kerberos4kth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libss0-kerberos4kth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"kerberos4kth-clients", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"kerberos4kth-clients-x", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"kerberos4kth-dev", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"kerberos4kth-docs", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"kerberos4kth-kdc", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"kerberos4kth-kip", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"kerberos4kth-servers", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"kerberos4kth-servers-x", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"kerberos4kth-services", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"kerberos4kth-user", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"kerberos4kth-x11", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"kerberos4kth1", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"krb5-admin-server", pkgver:"1.3.4-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"krb5-clients", pkgver:"1.3.4-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"krb5-doc", pkgver:"1.3.4-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"krb5-ftpd", pkgver:"1.3.4-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"krb5-kdc", pkgver:"1.3.4-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"krb5-rsh-server", pkgver:"1.3.4-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"krb5-telnetd", pkgver:"1.3.4-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"krb5-user", pkgver:"1.3.4-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkadm1-kerberos4kth", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkadm55", pkgver:"1.3.4-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkafs0-kerberos4kth", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkdb-1-kerberos4kth", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkrb-1-kerberos4kth", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkrb5-dev", pkgver:"1.3.4-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkrb53", pkgver:"1.3.4-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkthacl1-kerberos4kth", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libotp0-kerberos4kth", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libroken16-kerberos4kth", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libsl0-kerberos4kth", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libss0-kerberos4kth", pkgver:"1.2.2-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kerberos4kth-clients", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kerberos4kth-clients-x", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kerberos4kth-dev", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kerberos4kth-docs", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kerberos4kth-kdc", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kerberos4kth-kip", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kerberos4kth-servers", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kerberos4kth-servers-x", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kerberos4kth-services", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kerberos4kth-user", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kerberos4kth-x11", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kerberos4kth1", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-admin-server", pkgver:"1.3.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-clients", pkgver:"1.3.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-doc", pkgver:"1.3.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-ftpd", pkgver:"1.3.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-kdc", pkgver:"1.3.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-rsh-server", pkgver:"1.3.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-telnetd", pkgver:"1.3.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-user", pkgver:"1.3.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkadm1-kerberos4kth", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkadm55", pkgver:"1.3.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkafs0-kerberos4kth", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkdb-1-kerberos4kth", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkrb-1-kerberos4kth", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkrb5-dev", pkgver:"1.3.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkrb53", pkgver:"1.3.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkthacl1-kerberos4kth", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libotp0-kerberos4kth", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libroken16-kerberos4kth", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libsl0-kerberos4kth", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libss0-kerberos4kth", pkgver:"1.2.2-11.1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kerberos4kth-clients / kerberos4kth-clients-x / kerberos4kth-dev / etc");
}
