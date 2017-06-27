#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:102. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(48144);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/07/20 01:56:56 $");

  script_cve_id("CVE-2009-1191");
  script_xref(name:"MDVSA", value:"2009:102");

  script_name(english:"Mandriva Linux Security Advisory : apache (MDVSA-2009:102)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been found and corrected in apache :

mod_proxy_ajp.c in the mod_proxy_ajp module in the Apache HTTP Server
2.2.11 allows remote attackers to obtain sensitive response data,
intended for a client that sent an earlier POST request with no
request body, via an HTTP request (CVE-2009-1191).

This update provides fixes for that vulnerability."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-htcacheclean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_authn_dbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_dav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_dbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_disk_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_file_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_mem_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_proxy_ajp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_userdir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mpm-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mpm-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mpm-peruser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.1", reference:"apache-base-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-devel-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-htcacheclean-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mod_authn_dbd-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mod_cache-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mod_dav-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mod_dbd-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mod_deflate-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mod_disk_cache-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mod_file_cache-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mod_ldap-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mod_mem_cache-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mod_proxy-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mod_proxy_ajp-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mod_ssl-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mod_userdir-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-modules-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mpm-event-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mpm-itk-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mpm-peruser-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mpm-prefork-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-mpm-worker-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"apache-source-2.2.11-10.1mdv2009.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
