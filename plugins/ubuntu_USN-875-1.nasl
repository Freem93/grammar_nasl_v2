#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-875-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43368);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2008-4192", "CVE-2008-4579", "CVE-2008-4580", "CVE-2008-6552", "CVE-2008-6560");
  script_bugtraq_id(30898, 31904, 32179, 37416);
  script_osvdb_id(48268, 49166, 50046, 50047, 50300, 56410);
  script_xref(name:"USN", value:"875-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 : redhat-cluster, redhat-cluster-suite vulnerabilities (USN-875-1)");
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
"Multiple insecure temporary file handling vulnerabilities were
discovered in Red Hat Cluster. A local attacker could exploit these to
overwrite arbitrary local files via symlinks. (CVE-2008-4192,
CVE-2008-4579, CVE-2008-4580, CVE-2008-6552)

It was discovered that CMAN did not properly handle malformed
configuration files. An attacker could cause a denial of service (via
CPU consumption and memory corruption) in a node if the attacker were
able to modify the cluster configuration for the node. (CVE-2008-6560).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ccs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fence");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fence-gnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gfs2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnbd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnbd-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gulm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libccs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libccs-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libccs3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcman-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcman1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcman2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcman3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdlm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdlm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdlm2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdlm3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdlmcontrol-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdlmcontrol3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfence-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfence3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgulm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgulm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libiddev-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagma-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagma1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:magma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:magma-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:redhat-cluster-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:redhat-cluster-suite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:redhat-cluster-suite-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rgmanager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"ccs", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"cman", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fence", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fence-gnbd", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gfs-tools", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gnbd-client", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gnbd-server", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gulm", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libccs-dev", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcman-dev", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcman1", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdlm-dev", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdlm1", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgulm-dev", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgulm1", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libiddev-dev", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmagma-dev", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmagma1", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"magma", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"magma-plugins", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"redhat-cluster-suite", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"redhat-cluster-suite-source", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"rgmanager", pkgver:"1.20060222-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cman", pkgver:"2.20080227-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gfs-tools", pkgver:"2.20080227-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gfs2-tools", pkgver:"2.20080227-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gnbd-client", pkgver:"2.20080227-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gnbd-server", pkgver:"2.20080227-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcman-dev", pkgver:"2.20080227-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcman2", pkgver:"2.20080227-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libdlm-dev", pkgver:"2.20080227-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libdlm2", pkgver:"2.20080227-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"redhat-cluster-source", pkgver:"2.20080227-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"redhat-cluster-suite", pkgver:"2.20080227-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"rgmanager", pkgver:"2.20080227-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cman", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gfs-tools", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gfs2-tools", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gnbd-client", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gnbd-server", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libccs-dev", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libccs-perl", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libccs3", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcman-dev", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libcman3", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libdlm-dev", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libdlm3", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libdlmcontrol-dev", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libdlmcontrol3", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libfence-dev", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libfence3", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"redhat-cluster-source", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"redhat-cluster-suite", pkgver:"2.20080826-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"rgmanager", pkgver:"2.20080826-0ubuntu1.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ccs / cman / fence / fence-gnbd / gfs-tools / gfs2-tools / etc");
}
