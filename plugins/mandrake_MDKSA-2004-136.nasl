#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:136. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(15769);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:56 $");

  script_cve_id("CVE-2004-0882");
  script_xref(name:"MDKSA", value:"2004:136");

  script_name(english:"Mandrake Linux Security Advisory : samba (MDKSA-2004:136)");
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
"Steffan Esser discovered that invalid bounds checking in reply to
certain trans2 requests could result in a buffer overrun in smbd. This
can only be exploited by a malicious user able to create files with
very specific Unicode filenames on a samba share.

The updated packages have been patched to prevent this problem."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbclient0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbclient0-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbclient0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbclient0-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss_wins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-passdb-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-passdb-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-passdb-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-vscan-clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-vscan-icap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/19");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64smbclient0-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64smbclient0-devel-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64smbclient0-static-devel-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsmbclient0-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsmbclient0-devel-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libsmbclient0-static-devel-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"nss_wins-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"samba-client-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"samba-common-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"samba-doc-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"samba-passdb-mysql-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"samba-passdb-pgsql-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"samba-passdb-xml-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"samba-server-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"samba-swat-3.0.6-4.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"samba-winbind-3.0.6-4.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64smbclient0-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64smbclient0-devel-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64smbclient0-static-devel-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libsmbclient0-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libsmbclient0-devel-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libsmbclient0-static-devel-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"nss_wins-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"samba-client-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"samba-common-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"samba-doc-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"samba-passdb-mysql-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"samba-passdb-pgsql-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"samba-passdb-xml-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"samba-server-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"samba-swat-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"samba-vscan-clamav-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"samba-vscan-icap-3.0.7-2.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"samba-winbind-3.0.7-2.2.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
