#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:185. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24570);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/03/19 14:49:26 $");

  script_cve_id("CVE-2006-4625", "CVE-2006-5178");
  script_bugtraq_id(19933);
  script_xref(name:"MDKSA", value:"2006:185");

  script_name(english:"Mandrake Linux Security Advisory : php (MDKSA-2006:185)");
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
"PHP 4.x up to 4.4.4 and PHP 5 up to 5.1.6 allows local users to bypass
certain Apache HTTP Server httpd.conf options, such as safe_mode and
open_basedir, via the ini_restore function, which resets the values to
their php.ini (Master Value) defaults. (CVE-2006-4625)

A race condition in the symlink function in PHP 5.1.6 and earlier
allows local users to bypass the open_basedir restriction by using a
combination of symlink, mkdir, and unlink functions to change the file
path after the open_basedir check and before the file is opened by the
underlying system, as demonstrated by symlinking a symlink into a
subdirectory, to point to a parent directory via .. (dot dot)
sequences, and then unlinking the resulting symlink. (CVE-2006-5178)

Because the design flaw cannot be solved it is strongly recommended to
disable the symlink() function if you are using the open_basedir
feature. You can achieve that by adding symlink to the list of
disabled functions within your php.ini: disable_functions=...,symlink

The updated packages do not alter the system php.ini.

Updated packages have been patched to correct the CVE-2006-4625 issue.
Users must restart Apache for the changes to take effect."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fcgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64php5_common5-5.0.4-9.16.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libphp5_common5-5.0.4-9.16.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-cgi-5.0.4-9.16.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-cli-5.0.4-9.16.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-devel-5.0.4-9.16.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"php-fcgi-5.0.4-9.16.20060mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64php5_common5-5.1.6-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libphp5_common5-5.1.6-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-cgi-5.1.6-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-cli-5.1.6-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-devel-5.1.6-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-fcgi-5.1.6-1.2mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
