#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:120. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(22020);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/03/19 14:42:14 $");

  script_cve_id("CVE-2006-3403");
  script_bugtraq_id(18927);
  script_xref(name:"MDKSA", value:"2006:120");

  script_name(english:"Mandrake Linux Security Advisory : samba (MDKSA-2006:120)");
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
"A vulnerability in samba 3.0.x was discovered where an attacker could
cause a single smbd process to bloat, exhausting memory on the system.
This bug is caused by continually increasing the size of an array
which maintains state information about the number of active share
connections.

Updated packages have been patched to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/security/CVE-2006-3403.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbclient0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbclient0-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbclient0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbclient0-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mount-cifs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss_wins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-passdb-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-passdb-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-passdb-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-smbldap-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-vscan-clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-vscan-icap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64smbclient0-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64smbclient0-devel-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64smbclient0-static-devel-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libsmbclient0-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libsmbclient0-devel-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libsmbclient0-static-devel-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"mount-cifs-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"nss_wins-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"samba-client-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"samba-common-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"samba-doc-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"samba-passdb-mysql-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"samba-passdb-pgsql-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"samba-passdb-xml-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"samba-server-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"samba-smbldap-tools-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"samba-swat-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"samba-vscan-clamav-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"samba-vscan-icap-3.0.13-2.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"samba-winbind-3.0.13-2.1.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64smbclient0-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64smbclient0-devel-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64smbclient0-static-devel-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libsmbclient0-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libsmbclient0-devel-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libsmbclient0-static-devel-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mount-cifs-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"nss_wins-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"samba-client-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"samba-common-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"samba-doc-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"samba-passdb-mysql-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"samba-passdb-pgsql-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"samba-passdb-xml-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"samba-server-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"samba-smbldap-tools-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"samba-swat-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"samba-vscan-clamav-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"samba-vscan-icap-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"samba-winbind-3.0.20-3.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
