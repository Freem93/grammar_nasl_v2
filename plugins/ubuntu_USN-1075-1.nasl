#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1075-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52477);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2011-0719");
  script_bugtraq_id(46597);
  script_osvdb_id(71268);
  script_xref(name:"USN", value:"1075-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : samba vulnerability (USN-1075-1)");
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
"Volker Lendecke discovered that Samba incorrectly handled certain file
descriptors. A remote attacker could send a specially crafted request
to the server and cause Samba to crash or hang, resulting in a denial
of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-smbpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-common-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:smbfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/01");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libpam-smbpass", pkgver:"3.0.22-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsmbclient", pkgver:"3.0.22-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsmbclient-dev", pkgver:"3.0.22-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-samba", pkgver:"3.0.22-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba", pkgver:"3.0.22-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba-common", pkgver:"3.0.22-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba-dbg", pkgver:"3.0.22-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba-doc", pkgver:"3.0.22-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba-doc-pdf", pkgver:"3.0.22-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"smbclient", pkgver:"3.0.22-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"smbfs", pkgver:"3.0.22-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"swat", pkgver:"3.0.22-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"winbind", pkgver:"3.0.22-1ubuntu3.14")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpam-smbpass", pkgver:"3.0.28a-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsmbclient", pkgver:"3.0.28a-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsmbclient-dev", pkgver:"3.0.28a-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"samba", pkgver:"3.0.28a-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"samba-common", pkgver:"3.0.28a-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"samba-dbg", pkgver:"3.0.28a-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"samba-doc", pkgver:"3.0.28a-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"samba-doc-pdf", pkgver:"3.0.28a-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"smbclient", pkgver:"3.0.28a-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"smbfs", pkgver:"3.0.28a-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"swat", pkgver:"3.0.28a-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"winbind", pkgver:"3.0.28a-1ubuntu4.14")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libpam-smbpass", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libsmbclient", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libsmbclient-dev", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libwbclient0", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"samba", pkgver:"2:3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"samba-common", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"samba-common-bin", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"samba-dbg", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"samba-doc", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"samba-doc-pdf", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"samba-tools", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"smbclient", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"smbfs", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"swat", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"winbind", pkgver:"3.4.0-3ubuntu5.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpam-smbpass", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libsmbclient", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libsmbclient-dev", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libwbclient0", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"samba", pkgver:"2:3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"samba-common", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"samba-common-bin", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"samba-dbg", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"samba-doc", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"samba-doc-pdf", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"samba-tools", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"smbclient", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"smbfs", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"swat", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"winbind", pkgver:"3.4.7~dfsg-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libpam-smbpass", pkgver:"3.5.4~dfsg-1ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libsmbclient", pkgver:"3.5.4~dfsg-1ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libsmbclient-dev", pkgver:"3.5.4~dfsg-1ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libwbclient0", pkgver:"3.5.4~dfsg-1ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"samba", pkgver:"2:3.5.4~dfsg-1ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"samba-common", pkgver:"3.5.4~dfsg-1ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"samba-common-bin", pkgver:"3.5.4~dfsg-1ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"samba-dbg", pkgver:"3.5.4~dfsg-1ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"samba-doc", pkgver:"3.5.4~dfsg-1ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"samba-doc-pdf", pkgver:"3.5.4~dfsg-1ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"samba-tools", pkgver:"3.5.4~dfsg-1ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"smbclient", pkgver:"3.5.4~dfsg-1ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"swat", pkgver:"3.5.4~dfsg-1ubuntu8.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"winbind", pkgver:"3.5.4~dfsg-1ubuntu8.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpam-smbpass / libsmbclient / libsmbclient-dev / libwbclient0 / etc");
}
