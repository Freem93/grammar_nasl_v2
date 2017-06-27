#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:213. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20445);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/22 11:11:55 $");

  script_cve_id("CVE-2005-2491", "CVE-2005-3054", "CVE-2005-3319", "CVE-2005-3353", "CVE-2005-3388", "CVE-2005-3389", "CVE-2005-3390", "CVE-2005-3391", "CVE-2005-3392");
  script_xref(name:"MDKSA", value:"2005:213");

  script_name(english:"Mandrake Linux Security Advisory : php (MDKSA-2005:213)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of vulnerabilities were discovered in PHP :

An issue with fopen_wrappers.c would not properly restrict access to
other directories when the open_basedir directive included a trailing
slash (CVE-2005-3054); this issue does not affect Corporate Server
2.1.

An issue with the apache2handler SAPI in mod_php could allow an
attacker to cause a Denial of Service via the session.save_path option
in an .htaccess file or VirtualHost stanza (CVE-2005-3319); this issue
does not affect Corporate Server 2.1.

A Denial of Service vulnerability was discovered in the way that PHP
processes EXIF image data which could allow an attacker to cause PHP
to crash by supplying carefully crafted EXIF image data
(CVE-2005-3353).

A cross-site scripting vulnerability was discovered in the phpinfo()
function which could allow for the injection of JavaScript or HTML
content onto a page displaying phpinfo() output, or to steal data such
as cookies (CVE-2005-3388).

A flaw in the parse_str() function could allow for the enabling of
register_globals, even if it was disabled in the PHP configuration
file (CVE-2005-3389).

A vulnerability in the way that PHP registers global variables during
a file upload request could allow a remote attacker to overwrite the
$GLOBALS array which could potentially lead the execution of arbitrary
PHP commands. This vulnerability only affects systems with
register_globals enabled (CVE-2005-3390).

The updated packages have been patched to address this issue. Once the
new packages have been installed, you will need to restart your Apache
server using 'service httpd restart' in order for the new packages to
take effect ('service httpd2-naat restart' for MNF2)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory_182005.77.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory_192005.78.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory_202005.79.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php_common432");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp_common432");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php432-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64php_common432-4.3.8-3.6.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libphp_common432-4.3.8-3.6.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"php-cgi-4.3.8-3.6.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"php-cli-4.3.8-3.6.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"php432-devel-4.3.8-3.6.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64php_common432-4.3.10-7.4.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libphp_common432-4.3.10-7.4.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"php-cgi-4.3.10-7.4.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"php-cli-4.3.10-7.4.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"php432-devel-4.3.10-7.4.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64php5_common5-5.0.4-9.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libphp5_common5-5.0.4-9.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-cgi-5.0.4-9.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-cli-5.0.4-9.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-devel-5.0.4-9.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-exif-5.0.4-1.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-fcgi-5.0.4-9.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
