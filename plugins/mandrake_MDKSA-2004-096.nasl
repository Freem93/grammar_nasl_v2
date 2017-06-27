#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:096. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14752);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/04/15 10:48:38 $");

  script_cve_id("CVE-2004-0747", "CVE-2004-0748", "CVE-2004-0751", "CVE-2004-0783", "CVE-2004-0786", "CVE-2004-0809");
  script_xref(name:"MDKSA", value:"2004:096");

  script_name(english:"Mandrake Linux Security Advisory : apache2 (MDKSA-2004:096)");
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
"Two Denial of Service conditions were discovered in the input filter
of mod_ssl, the module that enables apache to handle HTTPS requests.

Another vulnerability was discovered by the ASF security team using
the Codenomicon HTTP Test Tool. This vulnerability, in the apr-util
library, can possibly lead to arbitrary code execution if certain
non-default conditions are met (enabling the AP_ENABLE_EXCEPTION_HOOK
define).

As well, the SITIC have discovered a buffer overflow when Apache
expands environment variables in configuration files such as .htaccess
and httpd.conf, which can lead to possible privilege escalation. This
can only be done, however, if an attacker is able to place malicious
configuration files on the server.

Finally, a crash condition was discovered in the mod_dav module by
Julian Reschke, where sending a LOCK refresh request to an indirectly
locked resource could crash the server.

The updated packages have been patched to protect against these
vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.uniras.gov.uk/vuls/2004/403518/index.htm"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64apr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libapr0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"apache2-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-common-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-devel-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-manual-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_cache-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_dav-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_deflate-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_disk_cache-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_file_cache-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_ldap-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_mem_cache-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_proxy-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_ssl-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-modules-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-source-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64apr0-2.0.48-6.6.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libapr0-2.0.48-6.6.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"apache2-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-common-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-devel-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-manual-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_cache-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_dav-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_deflate-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_disk_cache-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_file_cache-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_ldap-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_mem_cache-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_proxy-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-mod_ssl-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-modules-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache2-source-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64apr0-2.0.47-6.9.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libapr0-2.0.47-6.9.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
