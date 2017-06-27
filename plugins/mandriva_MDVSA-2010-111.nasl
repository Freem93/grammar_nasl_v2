#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:111. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(46849);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:11:07 $");

  script_cve_id("CVE-2009-4880", "CVE-2009-4881", "CVE-2010-0015", "CVE-2010-0296", "CVE-2010-0830");
  script_bugtraq_id(36443, 37885, 40063);
  script_xref(name:"MDVSA", value:"2010:111");

  script_name(english:"Mandriva Linux Security Advisory : glibc (MDVSA-2010:111)");
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
"Multiple vulnerabilities was discovered and fixed in glibc :

Multiple integer overflows in the strfmon implementation in the GNU C
Library (aka glibc or libc6) 2.10.1 and earlier allow
context-dependent attackers to cause a denial of service (memory
consumption or application crash) via a crafted format string, as
demonstrated by a crafted first argument to the money_format function
in PHP, a related issue to CVE-2008-1391 (CVE-2009-4880).

Integer overflow in the __vstrfmon_l function in stdlib/strfmon_l.c in
the strfmon implementation in the GNU C Library (aka glibc or libc6)
before 2.10.1 allows context-dependent attackers to cause a denial of
service (application crash) via a crafted format string, as
demonstrated by the %99999999999999999999n string, a related issue to
CVE-2008-1391 (CVE-2009-4881).

nis/nss_nis/nis-pwd.c in the GNU C Library (aka glibc or libc6) 2.7
and Embedded GLIBC (EGLIBC) 2.10.2 adds information from the
passwd.adjunct.byname map to entries in the passwd map, which allows
remote attackers to obtain the encrypted passwords of NIS accounts by
calling the getpwnam function (CVE-2010-0015).

The encode_name macro in misc/mntent_r.c in the GNU C Library (aka
glibc or libc6) 2.11.1 and earlier, as used by ncpmount and
mount.cifs, does not properly handle newline characters in mountpoint
names, which allows local users to cause a denial of service (mtab
corruption), or possibly modify mount options and gain privileges, via
a crafted mount request (CVE-2010-0296).

Integer signedness error in the elf_get_dynamic_info function in
elf/dynamic-link.h in ld.so in the GNU C Library (aka glibc or libc6)
2.0.1 through 2.11.1, when the --verify option is used, allows
user-assisted remote attackers to execute arbitrary code via a crafted
ELF program with a negative value for a certain d_tag structure member
in the ELF header (CVE-2010-0830).

Packages for 2008.0 and 2009.0 are provided as of the Extended
Maintenance Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=4
90

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/09");
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
if (rpm_check(release:"MDK2008.0", reference:"glibc-2.6.1-4.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"glibc-devel-2.6.1-4.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"glibc-doc-2.6.1-4.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"glibc-doc-pdf-2.6.1-4.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"glibc-i18ndata-2.6.1-4.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"glibc-profile-2.6.1-4.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"glibc-static-devel-2.6.1-4.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"glibc-utils-2.6.1-4.4mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"nscd-2.6.1-4.4mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"glibc-2.8-1.20080520.5.5mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-devel-2.8-1.20080520.5.5mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-doc-2.8-1.20080520.5.5mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-doc-pdf-2.8-1.20080520.5.5mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-i18ndata-2.8-1.20080520.5.5mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-profile-2.8-1.20080520.5.5mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-static-devel-2.8-1.20080520.5.5mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"glibc-utils-2.8-1.20080520.5.5mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nscd-2.8-1.20080520.5.5mnb2")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"glibc-2.9-0.20081113.5.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-devel-2.9-0.20081113.5.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-doc-2.9-0.20081113.5.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-doc-pdf-2.9-0.20081113.5.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-i18ndata-2.9-0.20081113.5.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-profile-2.9-0.20081113.5.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-static-devel-2.9-0.20081113.5.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"glibc-utils-2.9-0.20081113.5.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nscd-2.9-0.20081113.5.1mnb2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
