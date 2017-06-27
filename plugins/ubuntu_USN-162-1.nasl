#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-162-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20568);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2005-1850", "CVE-2005-1851", "CVE-2005-1852", "CVE-2005-1916", "CVE-2005-2369", "CVE-2005-2370", "CVE-2005-2448");
  script_xref(name:"USN", value:"162-1");

  script_name(english:"Ubuntu 5.04 : ekg vulnerabilities (USN-162-1)");
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
"Marcin Owsiany and Wojtek Kaniewski discovered that some contributed
scripts (contrib/ekgh, contrib/ekgnv.sh, and contrib/getekg.sh) in the
ekg package created temporary files in an insecure way, which allowed
exploitation of a race condition to create or overwrite files with the
privileges of the user invoking the script. (CAN-2005-1850)

Marcin Owsiany and Wojtek Kaniewski discovered a shell command
injection vulnerability in a contributed utility
(contrib/scripts/ekgbot-pre1.py). By sending specially crafted content
to the bot, an attacker could exploit this to execute arbitrary code
with the privileges of the user running ekgbot. (CAN-2005-1851)

Marcin Slusarz discovered an integer overflow in the Gadu library. By
sending a specially crafted incoming message, a remote attacker could
execute arbitrary code with the privileges of the application using
libgadu. (CAN-2005-1852)

Eric Romang discovered that another contributed script
(contrib/scripts/linki.py) created temporary files in an insecure way,
which allowed exploitation of a race condition to create or overwrite
files with the privileges of the user invoking the script.
(CAN-2005-1916)

Grzegorz Jaskiewicz discovered several integer overflows in the Gadu
library. A remote attacker could exploit this to crash the Gadu client
application or even execute arbitrary code with the privileges of the
user by sending specially crafted messages. (CAN-2005-2369)

Szymon Zygmunt and Michal Bartoszkiewicz discovered a memory
alignment error in the Gadu library. By sending specially crafted
messages, a remote attacker could crash the application using the
library. (CAN-2005-2370)

Marcin Slusarz discovered that the Gadu library did not properly
handle endianess conversion in some cases. This caused invalid
behavior on big endian architectures. The only affected supported
architecture is powerpc. (CAN-2005-2448).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ekg, libgadu-dev and / or libgadu3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ekg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgadu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgadu3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
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
if (! ereg(pattern:"^(5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"ekg", pkgver:"1.5-4ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgadu-dev", pkgver:"1.5-4ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgadu3", pkgver:"1.5-4ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ekg / libgadu-dev / libgadu3");
}
