#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-288-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21613);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 16:22:51 $");

  script_cve_id("CVE-2006-2313", "CVE-2006-2314");
  script_bugtraq_id(18092);
  script_osvdb_id(25730, 25731);
  script_xref(name:"USN", value:"288-1");

  script_name(english:"Ubuntu 5.04 / 5.10 : postgresql-7.4/-8.0, postgresql, psycopg,  (USN-288-1)");
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
"CVE-2006-2313: Akio Ishida and Yasuo Ohgaki discovered a weakness in
the handling of invalidly-encoded multibyte text data. If a client
application processed untrusted input without respecting its encoding
and applied standard string escaping techniques (such as replacing a
single quote >>'<< with >>\'<< or >>''<<), the PostgreSQL server could
interpret the resulting string in a way that allowed an attacker to
inject arbitrary SQL commands into the resulting SQL query. The
PostgreSQL server has been modified to reject such invalidly encoded
strings now, which completely fixes the problem for some 'safe'
multibyte encodings like UTF-8.

CVE-2006-2314: However, there are some less popular and client-only
multibyte encodings (such as SJIS, BIG5, GBK, GB18030, and UHC) which
contain valid multibyte characters that end with the byte 0x5c, which
is the representation of the backslash character >>\<< in ASCII. Many
client libraries and applications use the non-standard, but popular
way of escaping the >>'<< character by replacing all occurences of it
with >>\'<<. If a client application uses one of the affected
encodings and does not interpret multibyte characters, and an attacker
supplies a specially crafted byte sequence as an input string
parameter, this escaping method would then produce a validly-encoded
character and an excess >>'<< character which would end the string.
All subsequent characters would then be interpreted as SQL code, so
the attacker could execute arbitrary SQL commands.

To fix this vulnerability end-to-end, client-side applications must be
fixed to properly interpret multibyte encodings and use >>''<< instead
of >>\'<<. However, as a precautionary measure, the sequence >>\'<< is
now regarded as invalid when one of the affected client encodings is
in use. If you depend on the previous behaviour, you can restore it by
setting 'backslash_quote = on' in postgresql.conf. However, please be
aware that this could render you vulnerable again.

This issue does not affect you if you only use single-byte
(like SQL_ASCII or the ISO-8859-X family) or unaffected
multibyte (like UTF-8) encodings.

Please see http://www.postgresql.org/docs/techdocs.50 for further
details.

The psycopg and python-pgsql packages have been updated to
consistently use >>''<< for escaping quotes in strings.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-compat2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecpg5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtcl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpgtypes2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpq4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-client-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-contrib-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-contrib-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-doc-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-doc-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plperl-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-plpython-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-pltcl-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-7.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-server-dev-8.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-psycopg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-psycopg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-psycopg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:zope2.7-psycopgda");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/22");
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
if (! ereg(pattern:"^(5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"libecpg-dev", pkgver:"7.4.7-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libecpg4", pkgver:"7.4.7-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpgtcl", pkgver:"7.4.7-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpgtcl-dev", pkgver:"7.4.7-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpq3", pkgver:"7.4.7-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql", pkgver:"7.4.7-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-client", pkgver:"7.4.7-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-contrib", pkgver:"7.4.7-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-dev", pkgver:"7.4.7-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postgresql-doc", pkgver:"7.4.7-2ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python-pgsql", pkgver:"2.4.0-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python-psycopg", pkgver:"1.1.18-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-pgsql", pkgver:"2.4.0-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-psycopg", pkgver:"1.1.18-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.4-pgsql", pkgver:"2.4.0-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.4-psycopg", pkgver:"1.1.18-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"zope2.7-psycopgda", pkgver:"1.1.18-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libecpg-compat2", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libecpg-dev", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libecpg5", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpgtypes2", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpq-dev", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpq3", pkgver:"7.4.8-17ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libpq4", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-7.4", pkgver:"7.4.8-17ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-8.0", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-client-7.4", pkgver:"7.4.8-17ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-client-8.0", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-contrib-7.4", pkgver:"7.4.8-17ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-contrib-8.0", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-doc-7.4", pkgver:"7.4.8-17ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-doc-8.0", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-plperl-7.4", pkgver:"7.4.8-17ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-plperl-8.0", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-plpython-7.4", pkgver:"7.4.8-17ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-plpython-8.0", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-pltcl-7.4", pkgver:"7.4.8-17ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-pltcl-8.0", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-server-dev-7.4", pkgver:"7.4.8-17ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postgresql-server-dev-8.0", pkgver:"8.0.3-15ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python-pgsql", pkgver:"2.4.0-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python-psycopg", pkgver:"1.1.18-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.3-pgsql", pkgver:"2.4.0-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.3-psycopg", pkgver:"1.1.18-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4-pgsql", pkgver:"2.4.0-6ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4-psycopg", pkgver:"1.1.18-1ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"zope2.7-psycopgda", pkgver:"1.1.18-1ubuntu6.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libecpg-compat2 / libecpg-dev / libecpg4 / libecpg5 / libpgtcl / etc");
}
