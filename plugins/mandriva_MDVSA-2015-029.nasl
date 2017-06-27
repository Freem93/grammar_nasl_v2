#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:029. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81195);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/31 13:56:06 $");

  script_cve_id("CVE-2012-3509", "CVE-2014-8484", "CVE-2014-8485", "CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8503", "CVE-2014-8504", "CVE-2014-8737", "CVE-2014-8738");
  script_bugtraq_id(55281, 70714, 70741, 70761, 70866, 70868, 70869, 70908, 71083);
  script_xref(name:"MDVSA", value:"2015:029");
  script_xref(name:"MDVSA", value:"2015:029-1");

  script_name(english:"Mandriva Linux Security Advisory : binutils (MDVSA-2015:029-1)");
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
"Multiple vulnerabilities has been found and corrected in binutils :

Multiple integer overflows in the (1) _objalloc_alloc function in
objalloc.c and (2) objalloc_alloc macro in include/objalloc.h in GNU
libiberty, as used by binutils 2.22, allow remote attackers to cause a
denial of service (crash) via vectors related to the addition of
CHUNK_HEADER_SIZE to the length, which triggers a heap-based buffer
overflow (CVE-2012-3509).

The srec_scan function in bfd/srec.c in libdbfd in GNU binutils before
2.25 allows remote attackers to cause a denial of service
(out-of-bounds read) via a small S-record (CVE-2014-8484).

The setup_group function in bfd/elf.c in libbfd in GNU binutils 2.24
and earlier allows remote attackers to cause a denial of service
(crash) and possibly execute arbitrary code via crafted section group
headers in an ELF file (CVE-2014-8485).

The _bfd_XXi_swap_aouthdr_in function in bfd/peXXigen.c in GNU
binutils 2.24 and earlier allows remote attackers to cause a denial of
service (out-of-bounds write) and possibly have other unspecified
impact via a crafted NumberOfRvaAndSizes field in the AOUT header in a
PE executable (CVE-2014-8501).

Heap-based buffer overflow in the pe_print_edata function in
bfd/peXXigen.c in GNU binutils 2.24 and earlier allows remote
attackers to cause a denial of service (crash) and possibly have other
unspecified impact via a truncated export table in a PE file
(CVE-2014-8502).

Stack-based buffer overflow in the ihex_scan function in bfd/ihex.c in
GNU binutils 2.24 and earlier allows remote attackers to cause a
denial of service (crash) and possibly have other unspecified impact
via a crafted ihex file (CVE-2014-8503).

Stack-based buffer overflow in the srec_scan function in bfd/srec.c in
GNU binutils 2.24 and earlier allows remote attackers to cause a
denial of service (crash) and possibly have other unspecified impact
via a crafted file (CVE-2014-8504).

Multiple directory traversal vulnerabilities in GNU binutils 2.24 and
earlier allow local users to delete arbitrary files via a .. (dot dot)
or full path name in an archive to (1) strip or (2) objcopy or create
arbitrary files via (3) a .. (dot dot) or full path name in an archive
to ar (CVE-2014-8737).

The _bfd_slurp_extended_name_table function in bfd/archive.c in GNU
binutils 2.24 and earlier allows remote attackers to cause a denial of
service (invalid write, segmentation fault, and crash) via a crafted
extended name table in an archive (CVE-2014-8738).

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected binutils and / or lib64binutils-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64binutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"binutils-2.22-4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64binutils-devel-2.22-4.1.mbs1")) flag++;

if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"binutils-2.24-7.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64binutils-devel-2.24-7.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
