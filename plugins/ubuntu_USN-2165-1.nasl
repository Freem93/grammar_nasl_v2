#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2165-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73402);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/14 00:01:15 $");

  script_cve_id("CVE-2014-0076", "CVE-2014-0160");
  script_bugtraq_id(66363);
  script_xref(name:"USN", value:"2165-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.10 : openssl vulnerabilities (USN-2165-1)");
  script_summary(english:"Checks dpkg output for updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Neel Mehta discovered that OpenSSL incorrectly handled memory in the
TLS heartbeat extension. An attacker could use this issue to obtain up
to 64k of memory contents from the client or server, possibly leading
to the disclosure of private keys and other sensitive information.
(CVE-2014-0160)

Yuval Yarom and Naomi Benger discovered that OpenSSL incorrectly
handled timing during swap operations in the Montgomery ladder
implementation. An attacker could use this issue to perform
side-channel attacks and possibly recover ECDSA nonces.
(CVE-2014-0076)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libssl1.0.0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenSSL Heartbeat Information Leak');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014 Canonical, Inc. / NASL script (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}



include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/Ubuntu/release") ) audit(AUDIT_OS_NOT, "Ubuntu");
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;


if (ubuntu_check(osver:"12.04", pkgname:"libssl1.0.0", pkgver:"1.0.1-4ubuntu5.12")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libssl1.0.0", pkgver:"1.0.1c-3ubuntu2.7")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"libssl1.0.0", pkgver:"1.0.1e-3ubuntu1.2")) flag++;

if (flag)
{
  report = ubuntu_report_get();
  if (!egrep(pattern:"Installed package.+libssl1\.0\.0.+1\.0\.1", string:report)) exit(0, "The remote host does not use OpenSSL 1.0.1.");

  if (report_verbosity > 0) security_hole(port:0, extra:ubuntu_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
