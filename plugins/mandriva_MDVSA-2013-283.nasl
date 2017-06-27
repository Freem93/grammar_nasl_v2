#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:283. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(71092);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/11/26 11:49:45 $");

  script_cve_id("CVE-2012-4412", "CVE-2012-4424", "CVE-2013-2207", "CVE-2013-4237", "CVE-2013-4332", "CVE-2013-4458", "CVE-2013-4788");
  script_bugtraq_id(55462, 55543, 61183, 61729, 61960, 62324, 63299);
  script_xref(name:"MDVSA", value:"2013:283");

  script_name(english:"Mandriva Linux Security Advisory : glibc (MDVSA-2013:283)");
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
"Updated glibc packages fixes the following security issues :

Integer overflow in string/strcoll_l.c in the GNU C Library (aka glibc
or libc6) 2.17 and earlier allows context-dependent attackers to cause
a denial of service (crash) or possibly execute arbitrary code via a
long string, which triggers a heap-based buffer overflow
(CVE-2012-4412).

Stack-based buffer overflow in string/strcoll_l.c in the GNU C Library
(aka glibc or libc6) 2.17 and earlier allows context-dependent
attackers to cause a denial of service (crash) or possibly execute
arbitrary code via a long string that triggers a malloc failure and
use of the alloca function (CVE-2012-4424).

pt_chown in GNU C Library (aka glibc or libc6) before 2.18 does not
properly check permissions for tty files, which allows local users to
change the permission on the files and obtain access to arbitrary
pseudo-terminals by leveraging a FUSE file system (CVE-2013-2207).
NOTE! This is fixed by removing pt_chown wich may break chroots if
their devpts was not mounted correctly (make sure to mount the devpts
correctly with gid=5).

sysdeps/posix/readdir_r.c in the GNU C Library (aka glibc or libc6)
2.18 and earlier allows context-dependent attackers to cause a denial
of service (out-of-bounds write and crash) or possibly execute
arbitrary code via a crafted (1) NTFS or (2) CIFS image
(CVE-2013-4237).

Multiple integer overflows in malloc/malloc.c in the GNU C Library
(aka glibc or libc6) 2.18 and earlier allow context-dependent
attackers to cause a denial of service (heap corruption) via a large
value to the (1) pvalloc, (2) valloc, (3) posix_memalign, (4)
memalign, or (5) aligned_alloc functions (CVE-2013-4332).

A stack (frame) overflow flaw, which led to a denial of service
(application crash), was found in the way glibc's getaddrinfo()
function processed certain requests when called with AF_INET6. A
similar flaw to CVE-2013-1914, this affects AF_INET6 rather than
AF_UNSPEC (CVE-2013-4458).

The PTR_MANGLE implementation in the GNU C Library (aka glibc or
libc6) 2.4, 2.17, and earlier, and Embedded GLIBC (EGLIBC) does not
initialize the random value for the pointer guard, which makes it
easier for context- dependent attackers to control execution flow by
leveraging a buffer-overflow vulnerability in an application and using
the known zero value pointer guard to calculate a pointer address
(CVE-2013-4788).

Other fixes in this update :

  - Correct the processing of '\x80' characters in
    crypt_freesec.c

    - fix typo in nscd.service"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2013-0340.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"glibc-2.14.1-12.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"glibc-devel-2.14.1-12.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"glibc-doc-2.14.1-12.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"glibc-doc-pdf-2.14.1-12.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"glibc-i18ndata-2.14.1-12.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"glibc-profile-2.14.1-12.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"glibc-static-devel-2.14.1-12.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"glibc-utils-2.14.1-12.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"nscd-2.14.1-12.2.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
