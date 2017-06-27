#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-288-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27859);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/26 16:22:51 $");

  script_cve_id("CVE-2006-2313", "CVE-2006-2314", "CVE-2006-2753");
  script_xref(name:"USN", value:"288-3");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : dovecot, exim4, postfix vulnerabilities (USN-288-3)");
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
"USN-288-1 described a PostgreSQL client vulnerability in the way the
>>'<< character is escaped in SQL queries. It was determined that the
PostgreSQL backends of Exim, Dovecot, and Postfix used this unsafe
escaping method.

For reference, these are the details of the original USN :

CVE-2006-2313: Akio Ishida and Yasuo Ohgaki discovered a weakness in
the handling of invalidly-encoded multibyte text data. If a client
application processed untrusted input without respecting its encoding
and applied standard string escaping techniques (such as replacing a
single quote >>'<< with >>\'<< or >>''<<), the PostgreSQL server could
interpret the resulting string in a way that allowed an attacker to
inject arbitrary SQL commands into the resulting SQL query. The
PostgreSQL server has been modified to reject such invalidly encoded
strings now, which completely fixes the problem for some 'safe'
multibyte encodings like UTF-8.

CVE-2006-2314: However, there are some less popular and
client-only multibyte encodings (such as SJIS, BIG5, GBK,
GB18030, and UHC) which contain valid multibyte characters
that end with the byte 0x5c, which is the representation of
the backslash character >>\<< in ASCII. Many client
libraries and applications use the non-standard, but popular
way of escaping the >>'<< character by replacing all
occurences of it with >>\'<<. If a client application uses
one of the affected encodings and does not interpret
multibyte characters, and an attacker supplies a specially
crafted byte sequence as an input string parameter, this
escaping method would then produce a validly-encoded
character and an excess >>'<< character which would end the
string. All subsequent characters would then be interpreted
as SQL code, so the attacker could execute arbitrary SQL
commands.

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

Please see http://www.postgresql.org/docs/techdocs.50 for
further details.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-pop3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-heavy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exim4-daemon-light");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eximon4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-pcre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postfix-tls");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
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

if (ubuntu_check(osver:"5.04", pkgname:"dovecot", pkgver:"0.99.13-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"dovecot-common", pkgver:"0.99.13-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"dovecot-imapd", pkgver:"0.99.13-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"dovecot-pop3d", pkgver:"0.99.13-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"exim4", pkgver:"4.34-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"exim4-base", pkgver:"4.34-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"exim4-config", pkgver:"4.34-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"exim4-daemon-heavy", pkgver:"4.34-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"exim4-daemon-light", pkgver:"4.34-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"eximon4", pkgver:"4.34-10ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postfix", pkgver:"2.1.5-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postfix-dev", pkgver:"2.1.5-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postfix-doc", pkgver:"2.1.5-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postfix-ldap", pkgver:"2.1.5-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postfix-mysql", pkgver:"2.1.5-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postfix-pcre", pkgver:"2.1.5-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postfix-pgsql", pkgver:"2.1.5-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"postfix-tls", pkgver:"2.1.5-9ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"dovecot", pkgver:"0.99.14-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"dovecot-common", pkgver:"0.99.14-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"dovecot-imapd", pkgver:"0.99.14-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"dovecot-pop3d", pkgver:"0.99.14-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"exim4", pkgver:"4.52-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"exim4-base", pkgver:"4.52-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"exim4-config", pkgver:"4.52-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"exim4-daemon-heavy", pkgver:"4.52-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"exim4-daemon-light", pkgver:"4.52-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"eximon4", pkgver:"4.52-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postfix", pkgver:"2.2.4-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postfix-dev", pkgver:"2.2.4-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postfix-doc", pkgver:"2.2.4-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postfix-ldap", pkgver:"2.2.4-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postfix-mysql", pkgver:"2.2.4-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postfix-pcre", pkgver:"2.2.4-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"postfix-pgsql", pkgver:"2.2.4-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dovecot-common", pkgver:"1.0.beta3-3ubuntu5.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dovecot-imapd", pkgver:"1.0.beta3-3ubuntu5.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dovecot-pop3d", pkgver:"1.0.beta3-3ubuntu5.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4", pkgver:"4.60-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-base", pkgver:"4.60-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-config", pkgver:"4.60-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-daemon-heavy", pkgver:"4.60-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"exim4-daemon-light", pkgver:"4.60-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"eximon4", pkgver:"4.60-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postfix", pkgver:"2.2.10-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postfix-dev", pkgver:"2.2.10-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postfix-doc", pkgver:"2.2.10-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postfix-ldap", pkgver:"2.2.10-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postfix-mysql", pkgver:"2.2.10-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postfix-pcre", pkgver:"2.2.10-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"postfix-pgsql", pkgver:"2.2.10-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot / dovecot-common / dovecot-imapd / dovecot-pop3d / exim4 / etc");
}
