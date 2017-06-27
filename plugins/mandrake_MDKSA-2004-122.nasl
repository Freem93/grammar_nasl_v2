#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:122. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(15602);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:47:36 $");

  script_cve_id("CVE-2004-0885");
  script_xref(name:"MDKSA", value:"2004:122");

  script_name(english:"Mandrake Linux Security Advisory : mod_ssl/apache2-mod_ssl (MDKSA-2004:122)");
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
"A vulnerability in mod_ssl was discovered by Hartmut Keil. After a
renegotiation, mod_ssl would fail to ensure that the requested cipher
suite is actually negotiated. The provided packages have been patched
to prevent this problem."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64apr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libapr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/02");
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
if (rpm_check(release:"MDK10.0", reference:"apache2-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-common-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-devel-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-manual-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_cache-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_dav-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_deflate-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_disk_cache-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_file_cache-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_ldap-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_mem_cache-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_proxy-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_ssl-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-modules-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-source-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64apr0-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libapr0-2.0.48-6.7.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mod_ssl-2.8.16-1.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"apache2-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-common-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-devel-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-manual-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_cache-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_dav-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_deflate-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_disk_cache-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_file_cache-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_ldap-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_mem_cache-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_proxy-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_ssl-2.0.50-4.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-modules-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-source-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-worker-2.0.50-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mod_ssl-2.8.19-1.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"apache2-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-common-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-devel-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-manual-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_cache-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_dav-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_deflate-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_disk_cache-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_file_cache-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_ldap-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_mem_cache-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_proxy-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_ssl-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-modules-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-source-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64apr0-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libapr0-2.0.47-6.10.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mod_ssl-2.8.15-1.3.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
