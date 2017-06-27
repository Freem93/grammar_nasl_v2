#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:133. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(23883);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/09/25 10:51:09 $");

  script_cve_id("CVE-2006-3747");
  script_xref(name:"MDKSA", value:"2006:133");

  script_name(english:"Mandrake Linux Security Advisory : apache (MDKSA-2006:133)");
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
"Mark Dowd, of McAffee Avert Labs, discovered a potential remotely
exploitable off-by-one flaw in Apache's mod_rewrite ldap scheme
handling.

In order for this to be exploitable, a number of conditions need to be
met including a) running a vulnerable version of Apache (1.3.28+,
2.0.46+, or 2.2.0+), b) enabling mod_rewrite, c) having a rewrite rule
that the remote user can influence the beginning of, and d) a
particular stack frame layout.

By default, RewriteEngine is not enabled in Mandriva Linux Apache
packages, and no RewriteRules are defined.

Updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Module mod_rewrite LDAP Protocol Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(189);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/16");
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
if (rpm_check(release:"MDK2006.0", reference:"apache-base-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-devel-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_cache-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_dav-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_deflate-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_disk_cache-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_file_cache-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_ldap-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_mem_cache-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_proxy-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mod_userdir-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-modules-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mpm-peruser-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mpm-prefork-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-mpm-worker-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"apache-source-2.0.54-13.3.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
