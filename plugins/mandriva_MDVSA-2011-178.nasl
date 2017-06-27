#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:178. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(56953);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/03/11 17:42:31 $");

  script_cve_id(
    "CVE-2011-0536",
    "CVE-2011-1071",
    "CVE-2011-1089",
    "CVE-2011-1095",
    "CVE-2011-1659",
    "CVE-2011-2483"
  );
  script_bugtraq_id(
    46563,
    46740,
    47370,
    49241
  );
  script_osvdb_id(
    66751,
    68721,
    72796,
    73407,
    74742,
    74883
  );
  script_xref(name:"MDVSA", value:"2011:178");

  script_name(english:"Mandriva Linux Security Advisory : glibc (MDVSA-2011:178)");
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

Multiple untrusted search path vulnerabilities in elf/dl-object.c in
certain modified versions of the GNU C Library (aka glibc or libc6),
including glibc-2.5-49.el5_5.6 and glibc-2.12-1.7.el6_0.3 in Red Hat
Enterprise Linux, allow local users to gain privileges via a crafted
dynamic shared object (DSO) in a subdirectory of the current working
directory during execution of a (1) setuid or (2) setgid program that
has in (a) RPATH or (b) RUNPATH. NOTE: this issue exists because of an
incorrect fix for CVE-2010-3847 (CVE-2011-0536).

The GNU C Library (aka glibc or libc6) before 2.12.2 and Embedded
GLIBC (EGLIBC) allow context-dependent attackers to execute arbitrary
code or cause a denial of service (memory consumption) via a long UTF8
string that is used in an fnmatch call, aka a stack extension attack,
a related issue to CVE-2010-2898, as originally reported for use of
this library by Google Chrome (CVE-2011-1071).

The addmntent function in the GNU C Library (aka glibc or libc6) 2.13
and earlier does not report an error status for failed attempts to
write to the /etc/mtab file, which makes it easier for local users to
trigger corruption of this file, as demonstrated by writes from a
process with a small RLIMIT_FSIZE value, a different vulnerability
than CVE-2010-0296 (CVE-2011-1089).

locale/programs/locale.c in locale in the GNU C Library (aka glibc or
libc6) before 2.13 does not quote its output, which might allow local
users to gain privileges via a crafted localization environment
variable, in conjunction with a program that executes a script that
uses the eval function (CVE-2011-1095).

Integer overflow in posix/fnmatch.c in the GNU C Library (aka glibc or
libc6) 2.13 and earlier allows context-dependent attackers to cause a
denial of service (application crash) via a long UTF8 string that is
used in an fnmatch call with a crafted pattern argument, a different
vulnerability than CVE-2011-1071 (CVE-2011-1659).

crypt_blowfish before 1.1, as used in glibc on certain platforms, does
not properly handle 8-bit characters, which makes it easier for
context-dependent attackers to determine a cleartext password by
leveraging knowledge of a password hash (CVE-2011-2483).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.1", reference:"glibc-2.11.1-8.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-devel-2.11.1-8.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-doc-2.11.1-8.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-doc-pdf-2.11.1-8.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-i18ndata-2.11.1-8.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-profile-2.11.1-8.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-static-devel-2.11.1-8.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"glibc-utils-2.11.1-8.3mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nscd-2.11.1-8.3mnb2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
