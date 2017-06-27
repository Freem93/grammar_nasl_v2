#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:187. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(26107);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2007-1375", "CVE-2007-1399", "CVE-2007-1900", "CVE-2007-2727", "CVE-2007-2728", "CVE-2007-2748", "CVE-2007-2756", "CVE-2007-2872", "CVE-2007-3799", "CVE-2007-3996", "CVE-2007-3998", "CVE-2007-4658", "CVE-2007-4670");
  script_xref(name:"MDKSA", value:"2007:187");

  script_name(english:"Mandrake Linux Security Advisory : php (MDKSA-2007:187)");
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
"Numerous vulnerabilities were discovered in the PHP scripting language
that are corrected with this update.

An integer overflow in the substr_compare() function allows
context-dependent attackers to read sensitive memory via a large value
in the length argument. This only affects PHP5 (CVE-2007-1375).

A stack-based buffer overflow in the zip:// URI wrapper in PECL ZIP
1.8.3 and earlier allowes remote attackers to execute arbitrary code
via a long zip:// URL. This only affects Corporate Server 4.0
(CVE-2007-1399).

A CRLF injection vulnerability in the FILTER_VALIDATE_EMAIL filter
could allow an attacker to inject arbitrary email headers via a
special email address. This only affects Mandriva Linux 2007.1
(CVE-2007-1900).

The mcrypt_create_iv() function calls php_rand_r() with an
uninitialized seed variable, thus always generating the same
initialization vector, which may allow an attacker to decrypt certain
data more easily because of the guessable encryption keys
(CVE-2007-2727).

The soap extension calls php_rand_r() with an uninitialized seec
variable, which has unknown impact and attack vectors; an issue
similar to that affecting mcrypt_create_iv(). This only affects PHP5
(CVE-2007-2728).

The substr_count() function allows attackers to obtain sensitive
information via unspecified vectors. This only affects PHP5
(CVE-2007-2748).

An infinite loop was found in the gd extension that could be used to
cause a denial of service if a script were forced to process certain
PNG images from untrusted sources (CVE-2007-2756).

An integer overflow flaw was found in the chunk_split() function that
ould possibly execute arbitrary code as the apache user if a remote
attacker was able to pass arbitrary data to the third argument of
chunk_split() (CVE-2007-2872).

A flaw in the PHP session cookie handling could allow an attacker to
create a cross-site cookie insertion attack if a victim followed an
untrusted carefully-crafted URL (CVE-2007-3799).

Various integer overflow flaws were discovered in the PHP gd extension
that could allow a remote attacker to execute arbitrary code as the
apache user (CVE-2007-3996).

A flaw in the wordwrap() frunction could result in a denial of ervice
if a remote attacker was able to pass arbitrary data to the function
(CVE-2007-3998).

A flaw in the money_format() function could result in an information
leak or denial of service if a remote attacker was able to pass
arbitrary data to this function; this situation would be unlikely
however (CVE-2007-4658).

A bug in the PHP session cookie handling could allow an attacker to
stop a victim from viewing a vulnerable website if the victim first
visited a malicious website under the control of the attacker who was
able to use that page to set a cookie for the vulnerable website
(CVE-2007-4670).

Updated packages have been patched to prevent these issues. In
addition, PECL ZIP version 1.8.10 is being provided for Corporate
Server 4.0."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64php5_common5-5.1.6-1.9mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libphp5_common5-5.1.6-1.9mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-cgi-5.1.6-1.9mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-cli-5.1.6-1.9mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-devel-5.1.6-1.9mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-fcgi-5.1.6-1.9mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-gd-5.1.6-1.3mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-mcrypt-5.1.6-1.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-soap-5.1.6-1.2mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64php5_common5-5.2.1-4.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libphp5_common5-5.2.1-4.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-cgi-5.2.1-4.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-cli-5.2.1-4.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-devel-5.2.1-4.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-fcgi-5.2.1-4.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-gd-5.2.1-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-mcrypt-5.2.1-1.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-openssl-5.2.1-4.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-soap-5.2.1-1.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-zlib-5.2.1-4.3mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
