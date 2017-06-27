#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:091. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(21602);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:56:38 $");

  script_cve_id("CVE-2006-1990", "CVE-2006-1991");
  script_xref(name:"MDKSA", value:"2006:091");

  script_name(english:"Mandrake Linux Security Advisory : php (MDKSA-2006:091)");
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
"An integer overflow in the wordwrap() function could allow attackers
to execute arbitrary code via certain long arguments that cause a
small buffer to be allocated, triggering a heap-based buffer overflow
(CVE-2006-1990).

The substr_compare() function in PHP 5.x and 4.4.2 could allow
attackers to cause a Denial of Service (memory access violation) via
an out-of-bounds offset argument (CVE-2006-1991).

The second vulnerability only affects Mandriva Linux 2006; earlier
versions shipped with older versions of PHP that do not contain the
substr_compare() function."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php_common432");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp_common432");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php432-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64php_common432-4.3.10-7.12.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libphp_common432-4.3.10-7.12.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"php-cgi-4.3.10-7.12.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"php-cli-4.3.10-7.12.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"php432-devel-4.3.10-7.12.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64php5_common5-5.0.4-9.9.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libphp5_common5-5.0.4-9.9.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-cgi-5.0.4-9.9.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-cli-5.0.4-9.9.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-devel-5.0.4-9.9.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-fcgi-5.0.4-9.9.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
