#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:090. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(46227);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id("CVE-2010-0547", "CVE-2010-0787");
  script_bugtraq_id(37992, 38326);
  script_xref(name:"MDVSA", value:"2010:090-1");

  script_name(english:"Mandriva Linux Security Advisory : samba (MDVSA-2010:090-1)");
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
"Multiple vulnerabilies has been found and corrected in samba :

client/mount.cifs.c in mount.cifs in smbfs in Samba does not verify
that the (1) device name and (2) mountpoint strings are composed of
valid characters, which allows local users to cause a denial of
service (mtab corruption) via a crafted string (CVE-2010-0547).

client/mount.cifs.c in mount.cifs in smbfs in Samba allows local users
to mount a CIFS share on an arbitrary mountpoint, and gain privileges,
via a symlink attack on the mountpoint directory file (CVE-2010-0787).

The updated packages have been patched to correct these issues.

Update :

It was discovered that the previous Samba update required libtalloc
from Samba4 package. Therefore, this update provides the required
packages in order to fix the issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ldb-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64dcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64dcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ldb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64samba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64samba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64talloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64talloc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tevent0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libldb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtalloc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtevent0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mount-cifs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tdb-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.0", reference:"ldb-utils-0.9.3-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64dcerpc-devel-0.0.1-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64dcerpc0-0.0.1-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ldb-devel-0.9.3-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ldb0-0.9.3-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ndr-devel-0.0.1-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ndr0-0.0.1-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64samba-hostconfig-devel-0.0.1-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64samba-hostconfig0-0.0.1-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64talloc-devel-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64talloc1-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64tdb-devel-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64tdb1-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64tevent-devel-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64tevent0-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libdcerpc-devel-0.0.1-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libdcerpc0-0.0.1-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libldb-devel-0.9.3-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libldb0-0.9.3-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libndr-devel-0.0.1-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libndr0-0.0.1-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libsamba-hostconfig-devel-0.0.1-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libsamba-hostconfig0-0.0.1-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libtalloc-devel-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libtalloc1-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libtdb-devel-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libtdb1-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libtevent-devel-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libtevent0-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"mount-cifs4-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"samba4-client-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"samba4-common-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"samba4-devel-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"samba4-pidl-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"samba4-python-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"samba4-server-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"samba4-test-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"tdb-utils-4.0.0-0.4.alpha8.1mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
