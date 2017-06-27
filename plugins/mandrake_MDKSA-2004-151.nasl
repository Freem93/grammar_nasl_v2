#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:151. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(15998);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:56 $");

  script_cve_id("CVE-2004-1018", "CVE-2004-1019", "CVE-2004-1020", "CVE-2004-1063", "CVE-2004-1064", "CVE-2004-1065");
  script_xref(name:"MDKSA", value:"2004:151");

  script_name(english:"Mandrake Linux Security Advisory : php (MDKSA-2004:151)");
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
"A number of vulnerabilities in PHP versions prior to 4.3.10 were
discovered by Stefan Esser. Some of these vulnerabilities were not
deemed to be severe enough to warrant CVE names, however the packages
provided, with the exception of the Corporate Server 2.1 packages,
include fixes for all of the vulnerabilities, thanks to the efforts of
the OpenPKG team who extracted and backported the fixes.

The vulnerabilities fixed in all provided packages include a fix for a
possible information disclosure, double free, and negative reference
index array underflow in deserialization code (CVE-2004-1019). As
well, the exif_read_data() function suffers from an overflow on a long
sectionname; this vulnerability was discovered by Ilia Alshanetsky
(CVE-2004-1065).

The other fixes that appear in Mandrakelinux 9.2 and newer packages
include a fix for out of bounds memory write access in shmop_write()
and integer overflow/underflows in the pack() and unpack() functions.
The addslashes() function did not properly escape '&#0;' correctly. A
directory bypass issue existed in safe_mode execution. There is an
issue of arbitrary file access through path truncation. Finally, the
'magic_quotes_gpc' functionality could lead to one level directory
traversal with file uploads."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisories/012004.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/release_4_3_10.php"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php_common432");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp_common432");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php432-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64php_common432-4.3.4-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libphp_common432-4.3.4-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"php-cgi-4.3.4-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"php-cli-4.3.4-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"php432-devel-4.3.4-4.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64php_common432-4.3.8-3.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libphp_common432-4.3.8-3.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"php-cgi-4.3.8-3.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"php-cli-4.3.8-3.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"php432-devel-4.3.8-3.2.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64php_common432-4.3.3-2.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libphp_common432-4.3.3-2.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"php-cgi-4.3.3-2.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"php-cli-4.3.3-2.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"php432-devel-4.3.3-2.3.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
