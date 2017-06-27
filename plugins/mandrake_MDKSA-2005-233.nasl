#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:233. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20464);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:51:58 $");

  script_cve_id("CVE-2005-2970");
  script_xref(name:"MDKSA", value:"2005:233");

  script_name(english:"Mandrake Linux Security Advisory : apache2 (MDKSA-2005:233)");
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
"A memory leak in the worker MPM in Apache 2 could allow remote
attackers to cause a Denial of Service (memory consumption) via
aborted commands in certain circumstances, which prevents the memory
for the transaction pool from being reused for other connections.

As well, this update addresses two bugs in the Mandriva 2006 Apache
packges where apachectl was missing and also a segfault that occured
when using the mod_ldap module."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_dav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_disk_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_file_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_mem_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_userdir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mpm-peruser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_dav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_disk_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_file_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_mem_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-peruser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
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
if (rpm_check(release:"MDK10.1", reference:"apache2-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-common-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-devel-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-manual-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_cache-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_dav-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_deflate-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_disk_cache-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_file_cache-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_ldap-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_mem_cache-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_proxy-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-modules-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-source-2.0.50-7.5.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-worker-2.0.50-7.5.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"apache2-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-common-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-devel-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-manual-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_cache-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_dav-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_deflate-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_disk_cache-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_file_cache-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_ldap-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_mem_cache-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_proxy-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-modules-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-peruser-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-source-2.0.53-9.3.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-worker-2.0.53-9.3.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"apache-base-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-devel-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_cache-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_dav-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_deflate-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_disk_cache-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_file_cache-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_ldap-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_mem_cache-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_proxy-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_userdir-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-modules-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mpm-peruser-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mpm-prefork-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mpm-worker-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-source-2.0.54-13.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
