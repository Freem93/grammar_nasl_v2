#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-603-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32029);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_cve_id("CVE-2008-1693");
  script_osvdb_id(44434);
  script_xref(name:"USN", value:"603-2");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : koffice vulnerability (USN-603-2)");
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
"USN-603-1 fixed vulnerabilities in poppler. This update provides the
corresponding updates for KWord, part of KOffice.

It was discovered that the poppler PDF library did not correctly
handle certain malformed embedded fonts. If a user or an automated
system were tricked into opening a malicious PDF, a remote attacker
could execute arbitrary code with user privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kchart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kexi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kformula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kivio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kivio-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koffice-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:koshell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kplato");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpresenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpresenter-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krita");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krita-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kspread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kthesaurus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kword-data");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"karbon", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kchart", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kexi", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kformula", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kivio", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kivio-data", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice-data", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice-dbg", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice-dev", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice-doc", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice-doc-html", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koffice-libs", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"koshell", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kplato", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kpresenter", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kpresenter-data", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krita", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krita-data", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kspread", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kthesaurus", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kugar", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kword", pkgver:"1:1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kword-data", pkgver:"1.5.0-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"karbon", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kchart", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kexi", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kformula", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kivio", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kivio-data", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice-data", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice-dbg", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice-dev", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice-doc", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice-doc-html", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koffice-libs", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"koshell", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kplato", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kpresenter", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kpresenter-data", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krita", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krita-data", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kspread", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kthesaurus", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kugar", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kword", pkgver:"1:1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kword-data", pkgver:"1.5.2-0ubuntu2.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"karbon", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"kchart", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"kexi", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"kformula", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"kivio", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"kivio-data", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"koffice", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"koffice-data", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"koffice-dbg", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"koffice-dev", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"koffice-doc", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"koffice-doc-html", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"koffice-libs", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"koshell", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"kplato", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"kpresenter", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"kpresenter-data", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"krita", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"krita-data", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"kspread", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"kthesaurus", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"kugar", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"kword", pkgver:"1:1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"kword-data", pkgver:"1.6.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"karbon", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kchart", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kexi", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kformula", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kivio", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kivio-data", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"koffice", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"koffice-data", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"koffice-dbg", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"koffice-dev", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"koffice-doc", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"koffice-doc-html", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"koffice-libs", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"koshell", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kplato", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kpresenter", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kpresenter-data", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"krita", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"krita-data", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kspread", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kthesaurus", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kugar", pkgver:"1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kword", pkgver:"1:1.6.3-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kword-data", pkgver:"1.6.3-0ubuntu5.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "karbon / kchart / kexi / kformula / kivio / kivio-data / koffice / etc");
}
