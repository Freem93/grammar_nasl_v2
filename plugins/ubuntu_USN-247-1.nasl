#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-247-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21055);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2006-0582");
  script_osvdb_id(22986);
  script_xref(name:"USN", value:"247-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : heimdal vulnerability (USN-247-1)");
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
"A privilege escalation flaw has been found in the heimdal rsh (remote
shell) server. This allowed an authenticated attacker to overwrite
arbitrary files and gain ownership of them.

Please note that the heimdal-servers package is not officially
supported in Ubuntu (it is in the 'universe' component of the
archive). However, this affects you if you use a customized version
built from the heimdal source package (which is supported).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-clients-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:heimdal-servers-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libasn1-6-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssapi1-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libhdb7-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt4-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv7-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkafs0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-17-heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"heimdal-clients", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"heimdal-clients-x", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"heimdal-dev", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"heimdal-docs", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"heimdal-kdc", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"heimdal-servers", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"heimdal-servers-x", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libasn1-6-heimdal", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libgssapi1-heimdal", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libhdb7-heimdal", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkadm5clnt4-heimdal", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkadm5srv7-heimdal", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkafs0-heimdal", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libkrb5-17-heimdal", pkgver:"0.6.2-3ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"heimdal-clients", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"heimdal-clients-x", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"heimdal-dev", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"heimdal-docs", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"heimdal-kdc", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"heimdal-servers", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"heimdal-servers-x", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libasn1-6-heimdal", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgssapi1-heimdal", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libhdb7-heimdal", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkadm5clnt4-heimdal", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkadm5srv7-heimdal", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkafs0-heimdal", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkrb5-17-heimdal", pkgver:"0.6.3-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"heimdal-clients", pkgver:"0.6.3-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"heimdal-clients-x", pkgver:"0.6.3-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"heimdal-dev", pkgver:"0.6.3-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"heimdal-docs", pkgver:"0.6.3-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"heimdal-kdc", pkgver:"0.6.3-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"heimdal-servers", pkgver:"0.6.3-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"heimdal-servers-x", pkgver:"0.6.3-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libasn1-6-heimdal", pkgver:"0.6.3-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgssapi1-heimdal", pkgver:"0.6.3-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libhdb7-heimdal", pkgver:"0.6.3-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkadm5clnt4-heimdal", pkgver:"0.6.3-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkadm5srv7-heimdal", pkgver:"0.6.3-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkafs0-heimdal", pkgver:"0.6.3-11ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkrb5-17-heimdal", pkgver:"0.6.3-11ubuntu1.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "heimdal-clients / heimdal-clients-x / heimdal-dev / heimdal-docs / etc");
}
