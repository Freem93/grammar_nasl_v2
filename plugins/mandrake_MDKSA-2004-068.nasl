#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:068. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14167);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/08/09 10:50:40 $");

  script_cve_id("CVE-2004-0594", "CVE-2004-0595");
  script_xref(name:"MDKSA", value:"2004:068");

  script_name(english:"Mandrake Linux Security Advisory : php (MDKSA-2004:068)");
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
"Stefan Esser discovered a remotely exploitable vulnerability in PHP
where a remote attacker could trigger a memory_limit request
termination in places where an interruption is unsafe. This could be
used to execute arbitrary code.

As well, Stefan Esser also found a vulnerability in the handling of
allowed tags within PHP's strip_tags() function. This could lead to a
number of XSS issues on sites that rely on strip_tags(); however, this
only seems to affect the Internet Explorer and Safari browsers.

The updated packages have been patched to correct the problem and all
users are encouraged to upgrade immediately."
  );
  # http://security.e-matters.de/advisories/112004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83c215d0"
  );
  # http://security.e-matters.de/advisories/122004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d4bce03"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php_common432");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp_common430");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp_common432");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php430-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php432-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64php_common432-4.3.4-4.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libphp_common432-4.3.4-4.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"php-cgi-4.3.4-4.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"php-cli-4.3.4-4.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"php432-devel-4.3.4-4.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"libphp_common430-430-11.2.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"php-cgi-4.3.1-11.2.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"php-cli-4.3.1-11.2.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"php430-devel-430-11.2.91mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64php_common432-4.3.3-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libphp_common432-4.3.3-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"php-cgi-4.3.3-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"php-cli-4.3.3-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"php432-devel-4.3.3-2.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
