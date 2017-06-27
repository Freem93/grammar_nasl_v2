#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:028. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(48171);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/28 21:39:24 $");

  script_cve_id("CVE-2009-0689", "CVE-2009-2537", "CVE-2009-2702");
  script_bugtraq_id(35446, 35510, 36229);
  script_osvdb_id(56255, 57746, 61187);
  script_xref(name:"MDVSA", value:"2010:028");

  script_name(english:"Mandriva Linux Security Advisory : kdelibs4 (MDVSA-2010:028)");
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
"Multiple vulnerabilities was discovered and corrected in kdelibs4 :

KDE KSSL in kdelibs 3.5.4, 4.2.4, and 4.3 does not properly handle a
\'\0\' (NUL) character in a domain name in the Subject Alternative
Name field of an X.509 certificate, which allows man-in-the-middle
attackers to spoof arbitrary SSL servers via a crafted certificate
issued by a legitimate Certification Authority, a related issue to
CVE-2009-2408 (CVE-2009-2702).

KDE Konqueror allows remote attackers to cause a denial of service
(memory consumption) via a large integer value for the length property
of a Select object, a related issue to CVE-2009-1692 (CVE-2009-2537).

The gdtoa (aka new dtoa) implementation in gdtoa/misc.c in libc in
FreeBSD 6.4 and 7.2, NetBSD 5.0, and OpenBSD 4.5 allows
context-dependent attackers to cause a denial of service (application
crash) or possibly have unspecified other impact via a large precision
value in the format argument to a printf function, related to an array
overrun. (CVE-2009-0689).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdelibs4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdelibs4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kde3support4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdecore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdefakes5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdesu5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdeui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdnssd4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kfile4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64khtml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kimproxy4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kio5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kjs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kjsapi4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kjsembed4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kmediaplayer4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64knewstuff2_4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64knotifyconfig4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kntlm4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kparts4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kpty4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krosscore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krossui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ktexteditor4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kunittest4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nepomuk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64plasma3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64solid4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64threadweaver4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkde3support4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdecore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdefakes5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdesu5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdeui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdnssd4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkfile4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkhtml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkimproxy4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkio5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkjs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkjsapi4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkjsembed4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkmediaplayer4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libknewstuff2_4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libknotifyconfig4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkntlm4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkparts4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkpty4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrosscore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrossui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libktexteditor4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkunittest4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnepomuk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libplasma3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsolid4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libthreadweaver4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
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
if (rpm_check(release:"MDK2010.0", reference:"kdelibs4-core-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kdelibs4-devel-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kde3support4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kdecore5-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kdefakes5-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kdesu5-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kdeui5-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kdnssd4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kfile4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64khtml5-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kimproxy4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kio5-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kjs4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kjsapi4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kjsembed4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kmediaplayer4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64knewstuff2_4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64knotifyconfig4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kntlm4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kparts4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kpty4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64krosscore4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64krossui4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64ktexteditor4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kunittest4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kutils4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64nepomuk4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64plasma3-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64solid4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64threadweaver4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkde3support4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkdecore5-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkdefakes5-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkdesu5-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkdeui5-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkdnssd4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkfile4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkhtml5-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkimproxy4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkio5-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkjs4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkjsapi4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkjsembed4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkmediaplayer4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libknewstuff2_4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libknotifyconfig4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkntlm4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkparts4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkpty4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkrosscore4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkrossui4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libktexteditor4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkunittest4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkutils4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libnepomuk4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libplasma3-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libsolid4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libthreadweaver4-4.3.2-11.14mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
