#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-725-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37810);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:37:18 $");

  script_xref(name:"USN", value:"725-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : kdepim vulnerability (USN-725-1)");
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
"It was discovered that Kmail did not adequately prevent execution of
arbitrary code when a user clicked on a URL to an executable within an
HTML mail. If a user clicked on a malicious URL and chose to execute
the file, a remote attacker could execute arbitrary code with user
privileges. This update changes KMail's behavior to instead launch a
helper program to view the file if the user chooses to execute such a
link.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:akonadi-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:akregator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kaddressbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kalarm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kandy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:karm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdepim-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdepim-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdepim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdepim-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdepim-kfile-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdepim-kio-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdepim-kresources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdepim-strigi-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdepim-wizards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kitchensync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kjots");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kleopatra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kmailcvt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:knode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:knotes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:konsolekalendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kontact");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:korganizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:korn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpilot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ktimetracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ktnef");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libindex0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libindex0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkcal2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkcal2b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdepim1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdepim1a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdepim4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkgantt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkgantt0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkholidays4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkleo4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkleopatra1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkleopatra1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkmime2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpgp4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpimexchange1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpimexchange1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpimidentities1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libksieve0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libksieve0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libksieve4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libktnef1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libktnef1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmaildir4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmimelib1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmimelib1c2a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmimelib4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:networkstatus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:networkstatus-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! ereg(pattern:"^(6\.06|7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"akregator", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kaddressbook", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kalarm", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kandy", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"karm", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdepim", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdepim-dev", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdepim-doc", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdepim-doc-html", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdepim-kfile-plugins", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdepim-kio-plugins", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdepim-kresources", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdepim-wizards", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kitchensync", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kleopatra", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kmail", pkgver:"4:3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kmailcvt", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"knode", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"knotes", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kode", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"konsolekalendar", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kontact", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"korganizer", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"korn", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kpilot", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ksync", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ktnef", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libindex0", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libindex0-dev", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkcal2-dev", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkcal2b", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkdepim1-dev", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkdepim1a", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkgantt0", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkgantt0-dev", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkleopatra1", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkleopatra1-dev", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkmime2", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkpimexchange1", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkpimexchange1-dev", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkpimidentities1", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libksieve0", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libksieve0-dev", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libktnef1", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libktnef1-dev", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmimelib1-dev", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmimelib1c2a", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"networkstatus", pkgver:"3.5.2-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"akregator", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kaddressbook", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kalarm", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kandy", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"karm", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kdepim", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kdepim-dbg", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kdepim-dev", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kdepim-doc", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kdepim-doc-html", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kdepim-kfile-plugins", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kdepim-kio-plugins", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kdepim-kresources", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kdepim-wizards", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kitchensync", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kleopatra", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kmail", pkgver:"4:3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kmailcvt", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"knode", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"knotes", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kode", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"konsolekalendar", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kontact", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"korganizer", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"korn", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"kpilot", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ktnef", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libindex0", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libindex0-dev", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkcal2-dev", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkcal2b", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkdepim1-dev", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkdepim1a", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkgantt0", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkgantt0-dev", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkleopatra1", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkleopatra1-dev", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkmime2", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkpimexchange1", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkpimexchange1-dev", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libkpimidentities1", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libksieve0", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libksieve0-dev", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libktnef1", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libktnef1-dev", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libmimelib1-dev", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libmimelib1c2a", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"networkstatus", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"networkstatus-dev", pkgver:"3.5.7enterprise20070926-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"akregator", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kaddressbook", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kalarm", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kandy", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"karm", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdepim", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdepim-dbg", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdepim-dev", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdepim-doc", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdepim-doc-html", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdepim-kfile-plugins", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdepim-kio-plugins", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdepim-kresources", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdepim-wizards", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kitchensync", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kleopatra", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kmail", pkgver:"4:3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kmailcvt", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"knode", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"knotes", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kode", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"konsolekalendar", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kontact", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"korganizer", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"korn", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kpilot", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ktnef", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libindex0", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libindex0-dev", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkcal2-dev", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkcal2b", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkdepim1-dev", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkdepim1a", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkgantt0", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkgantt0-dev", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkleopatra1", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkleopatra1-dev", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkmime2", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkpimexchange1", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkpimexchange1-dev", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkpimidentities1", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libksieve0", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libksieve0-dev", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libktnef1", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libktnef1-dev", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmimelib1-dev", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmimelib1c2a", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"networkstatus", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"networkstatus-dev", pkgver:"3.5.10-0ubuntu1~hardy3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"akonadi-kde", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"akregator", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kaddressbook", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kalarm", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdepim", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdepim-dbg", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdepim-dev", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdepim-doc", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdepim-kresources", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdepim-strigi-plugins", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kdepim-wizards", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kjots", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kleopatra", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kmail", pkgver:"4:4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"knode", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"knotes", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kode", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"konsolekalendar", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"kontact", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"korganizer", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ktimetracker", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ktnef", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libkdepim4", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libkholidays4", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libkleo4", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libkpgp4", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libksieve4", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmaildir4", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libmimelib4", pkgver:"4.1.4-0ubuntu1~intrepid2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "akonadi-kde / akregator / kaddressbook / kalarm / kandy / karm / etc");
}
