#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-432-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28027);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:17 $");

  script_cve_id("CVE-2007-1263");
  script_bugtraq_id(22757);
  script_xref(name:"USN", value:"432-2");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 : gnupg2, gpgme1.0 vulnerability (USN-432-2)");
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
"USN-432-1 fixed a vulnerability in GnuPG. This update provides the
corresponding updates for GnuPG2 and the GPGME library.

Gerardo Richarte from Core Security Technologies discovered that when
gnupg is used without --status-fd, there is no way to distinguish
initial unsigned messages from a following signed message. An attacker
could inject an unsigned message, which could fool the user into
thinking the message was entirely signed by the original sender.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgpgme11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgpgme11-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libgpgme11", pkgver:"1.1.0-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgpgme11-dev", pkgver:"1.1.0-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"gnupg-agent", pkgver:"1.9.21-0ubuntu5.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"gnupg2", pkgver:"1.9.21-0ubuntu5.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"gpgsm", pkgver:"1.9.21-0ubuntu5.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgpgme11", pkgver:"1.1.2-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgpgme11-dev", pkgver:"1.1.2-2ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnupg-agent / gnupg2 / gpgsm / libgpgme11 / libgpgme11-dev");
}
