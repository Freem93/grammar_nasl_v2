#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:043. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24675);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/31 23:56:40 $");

  script_cve_id("CVE-2007-0897", "CVE-2007-0898");
  script_xref(name:"MDKSA", value:"2007:043");

  script_name(english:"Mandrake Linux Security Advisory : clamav (MDKSA-2007:043)");
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
"Clam AntiVirus ClamAV before 0.90 does not close open file descriptors
under certain conditions, which allows remote attackers to cause a
denial of service (file descriptor consumption and failed scans) via
CAB archives with a cabinet header record length of zero, which causes
a function to return without closing a file descriptor.
(CVE-2007-0897)

Directory traversal vulnerability in clamd in Clam AntiVirus ClamAV
before 0.90 allows remote attackers to overwrite arbitrary files via a
.. (dot dot) in the id MIME header parameter in a multi-part message.
(CVE-2007-0898)

The update to 0.90 addresses these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clamd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64clamav1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64clamav1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libclamav1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libclamav1-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"clamav-0.90-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"clamav-db-0.90-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"clamav-milter-0.90-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"clamd-0.90-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64clamav1-0.90-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64clamav1-devel-0.90-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libclamav1-0.90-0.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libclamav1-devel-0.90-0.1.20060mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2007.0", reference:"clamav-0.90-1.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"clamav-db-0.90-1.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"clamav-milter-0.90-1.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"clamd-0.90-1.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64clamav1-0.90-1.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64clamav1-devel-0.90-1.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libclamav1-0.90-1.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libclamav1-devel-0.90-1.1mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
