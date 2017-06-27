#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2247-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76109);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/24 17:29:03 $");

  script_cve_id("CVE-2013-1068", "CVE-2013-4463", "CVE-2013-4469", "CVE-2013-6491", "CVE-2013-7130", "CVE-2014-0134", "CVE-2014-0167");
  script_bugtraq_id(63467, 63468, 65106, 65276, 66495, 66753, 68094);
  script_osvdb_id(105648);
  script_xref(name:"USN", value:"2247-1");

  script_name(english:"Ubuntu 12.04 LTS / 13.10 / 14.04 LTS : nova vulnerabilities (USN-2247-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Darragh O'Reilly discovered that OpenStack Nova did not properly set
up its sudo configuration. If a different flaw was found in OpenStack
Nova, this vulnerability could be used to escalate privileges. This
issue only affected Ubuntu 13.10 and Ubuntu 14.04 LTS. (CVE-2013-1068)

Bernhard M. Wiedemann and Pedraig Brady discovered that OpenStack Nova
did not properly verify the virtual size of a QCOW2 images. A remote
authenticated attacker could exploit this to create a denial of
service via disk consumption. This issue did not affect Ubuntu 14.04
LTS. (CVE-2013-4463, CVE-2013-4469)

JuanFra Rodriguez Cardoso discovered that OpenStack Nova did not
enforce SSL connections when Nova was configured to use QPid and
qpid_protocol is set to 'ssl'. If a remote attacker were able to
perform a man-in-the-middle attack, this flaw could be exploited to
view sensitive information. Ubuntu does not use QPid with Nova by
default. This issue did not affect Ubuntu 14.04 LTS. (CVE-2013-6491)

Loganathan Parthipan discovered that OpenStack Nova did not properly
create expected files during KVM live block migration. A remote
authenticated attacker could exploit this to obtain root disk snapshot
contents via ephemeral storage. This issue did not affect Ubuntu 14.04
LTS. (CVE-2013-7130)

Stanislaw Pitucha discovered that OpenStack Nova did not enforce the
image format when rescuing an instance. A remote authenticated
attacker could exploit this to read host files. In the default
installation, attackers would be isolated by the libvirt guest
AppArmor profile. This issue only affected Ubuntu 13.10.
(CVE-2014-0134)

Mark Heckmann discovered that OpenStack Nova did not enforce RBAC
policy when adding security group rules via the EC2 API. A remote
authenticated user could exploit this to gain unintended access to
this API. This issue only affected Ubuntu 13.10. (CVE-2014-0167).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-nova package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-nova");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|13\.10|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 13.10 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"python-nova", pkgver:"2012.1.3+stable-20130423-e52e6912-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"python-nova", pkgver:"1:2013.2.3-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python-nova", pkgver:"1:2014.1-0ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-nova");
}
