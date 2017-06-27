#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:277. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(42132);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/17 17:02:54 $");

  script_cve_id("CVE-2009-2813", "CVE-2009-2906", "CVE-2009-2948");
  script_bugtraq_id(36363, 36572, 36573);
  script_xref(name:"MDVSA", value:"2009:277");

  script_name(english:"Mandriva Linux Security Advisory : samba (MDVSA-2009:277)");
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
"Multiple vulnerabilities has been found and corrected in samba :

The SMB (aka Samba) subsystem in Apple Mac OS X 10.5.8, when Windows
File Sharing is enabled, does not properly handle errors in resolving
pathnames, which allows remote authenticated users to bypass intended
sharing restrictions, and read, create, or modify files, in certain
circumstances involving user accounts that lack home directories
(CVE-2009-2813).

smbd in Samba 3.0 before 3.0.37, 3.2 before 3.2.15, 3.3 before 3.3.8,
and 3.4 before 3.4.2 allows remote authenticated users to cause a
denial of service (infinite loop) via an unanticipated oplock break
notification reply packet (CVE-2009-2906).

mount.cifs in Samba 3.0 before 3.0.37, 3.2 before 3.2.15, 3.3 before
3.3.8 and 3.4 before 3.4.2, when mount.cifs is installed suid root,
does not properly enforce permissions, which allows local users to
read part of the credentials file and obtain the password by
specifying the path to the credentials file and using the --verbose or
-v option (CVE-2009-2948).

The versions of samba shipping with Mandriva Linux
CS4/MES5/2008.1/2009.0/2009.1 have been updated to the latest version
that includes the fixes for these issues. Additionally for 2009.1 the
version upgrade provides many upstream bug fixes such as improved
Windows(tm) 7 support. The version for CS3 has been patched to address
these security issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/security/CVE-2009-2813.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/security/CVE-2009-2906.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/security/CVE-2009-2948.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64netapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64netapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbclient0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbclient0-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64talloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64talloc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbclient0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbclient0-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtalloc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mount-cifs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss_wins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-vscan-icap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64smbclient0-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64smbclient0-devel-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64smbclient0-static-devel-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libsmbclient0-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libsmbclient0-devel-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libsmbclient0-static-devel-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"mount-cifs-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"nss_wins-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"samba-client-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"samba-common-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"samba-doc-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"samba-server-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"samba-swat-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"samba-vscan-icap-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"samba-winbind-3.0.37-0.1mdv2008.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64netapi-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64netapi0-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64smbclient0-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64smbclient0-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64smbclient0-static-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64smbsharemodes-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64smbsharemodes0-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64talloc-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64talloc1-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64tdb-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64tdb1-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64wbclient-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64wbclient0-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnetapi-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnetapi0-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libsmbclient0-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libsmbclient0-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libsmbclient0-static-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libsmbsharemodes-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libsmbsharemodes0-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libtalloc-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libtalloc1-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libtdb-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libtdb1-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libwbclient-devel-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libwbclient0-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mount-cifs-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nss_wins-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"samba-client-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"samba-common-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"samba-doc-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"samba-server-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"samba-swat-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"samba-winbind-3.2.15-0.1mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64netapi-devel-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64netapi0-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64smbclient0-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64smbclient0-devel-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64smbclient0-static-devel-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64smbsharemodes-devel-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64smbsharemodes0-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64wbclient-devel-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64wbclient0-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libnetapi-devel-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libnetapi0-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libsmbclient0-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libsmbclient0-devel-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libsmbclient0-static-devel-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libsmbsharemodes-devel-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libsmbsharemodes0-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libwbclient-devel-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libwbclient0-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"mount-cifs-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nss_wins-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"samba-client-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"samba-common-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"samba-doc-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"samba-server-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"samba-swat-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"samba-winbind-3.3.8-0.1mdv2009.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
