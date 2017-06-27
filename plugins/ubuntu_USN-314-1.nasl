#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-314-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27890);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:17 $");

  script_cve_id("CVE-2006-3403");
  script_bugtraq_id(18927);
  script_osvdb_id(27130);
  script_xref(name:"USN", value:"314-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : samba vulnerability (USN-314-1)");
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
"The Samba security team reported a Denial of Service vulnerability in
the handling of information about active connections. In certain
circumstances an attacker could continually increase the memory usage
of the smbd process by issuing a large number of share connection
requests. By draining all available memory, this could be exploited to
render the remote Samba server unusable.

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:smbfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04|5\.10|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"libpam-smbpass", pkgver:"3.0.10-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libsmbclient", pkgver:"3.0.10-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libsmbclient-dev", pkgver:"3.0.10-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.4-samba", pkgver:"3.0.10-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"samba", pkgver:"3.0.10-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"samba-common", pkgver:"3.0.10-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"samba-dbg", pkgver:"3.0.10-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"samba-doc", pkgver:"3.0.10-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"smbclient", pkgver:"3.0.10-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"smbfs", pkgver:"3.0.10-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"swat", pkgver:"3.0.10-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"winbind", pkgver:"3.0.10-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpam-smbpass", pkgver:"3.0.14a-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libsmbclient", pkgver:"3.0.14a-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libsmbclient-dev", pkgver:"3.0.14a-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4-samba", pkgver:"3.0.14a-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"samba", pkgver:"3.0.14a-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"samba-common", pkgver:"3.0.14a-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"samba-dbg", pkgver:"3.0.14a-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"samba-doc", pkgver:"3.0.14a-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"smbclient", pkgver:"3.0.14a-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"smbfs", pkgver:"3.0.14a-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"swat", pkgver:"3.0.14a-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"winbind", pkgver:"3.0.14a-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpam-smbpass", pkgver:"3.0.22-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsmbclient", pkgver:"3.0.22-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsmbclient-dev", pkgver:"3.0.22-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-samba", pkgver:"3.0.22-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba", pkgver:"3.0.22-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba-common", pkgver:"3.0.22-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba-dbg", pkgver:"3.0.22-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba-doc", pkgver:"3.0.22-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba-doc-pdf", pkgver:"3.0.22-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"smbclient", pkgver:"3.0.22-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"smbfs", pkgver:"3.0.22-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"swat", pkgver:"3.0.22-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"winbind", pkgver:"3.0.22-1ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpam-smbpass / libsmbclient / libsmbclient-dev / python2.4-samba / etc");
}
