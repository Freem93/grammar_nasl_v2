#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:015. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20794);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:56:38 $");

  script_cve_id("CVE-2005-3538", "CVE-2005-3539");
  script_xref(name:"MDKSA", value:"2006:015");

  script_name(english:"Mandrake Linux Security Advisory : hylafax (MDKSA-2006:015)");
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
"Patrice Fournier discovered the faxrcvd/notify scripts (executed as
the uucp/fax user) run user-supplied input through eval without any
attempt at sanitising it first. This would allow any user who could
submit jobs to HylaFAX, or through telco manipulation control the
representation of callid information presented to HylaFAX to run
arbitrary commands as the uucp/fax user. (CVE-2005-3539, only 'notify'
in the covered versions)

Updated packages were also reviewed for vulnerability to an issue
where if PAM is disabled, a user could log in with no password.
(CVE-2005-3538)

In addition, some fixes to the packages for permissions, and the
%pre/%post scripts were backported from cooker. (#19679)

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hylafax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hylafax-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hylafax-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64hylafax4.2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64hylafax4.2.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libhylafax4.2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libhylafax4.2.0-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", reference:"hylafax-4.2.0-1.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"hylafax-client-4.2.0-1.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"hylafax-server-4.2.0-1.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64hylafax4.2.0-4.2.0-1.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64hylafax4.2.0-devel-4.2.0-1.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libhylafax4.2.0-4.2.0-1.4.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libhylafax4.2.0-devel-4.2.0-1.4.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"hylafax-4.2.0-3.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"hylafax-client-4.2.0-3.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"hylafax-server-4.2.0-3.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64hylafax4.2.0-4.2.0-3.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64hylafax4.2.0-devel-4.2.0-3.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libhylafax4.2.0-4.2.0-3.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libhylafax4.2.0-devel-4.2.0-3.2.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"hylafax-4.2.1-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"hylafax-client-4.2.1-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"hylafax-server-4.2.1-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64hylafax4.2.0-4.2.1-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64hylafax4.2.0-devel-4.2.1-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libhylafax4.2.0-4.2.1-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libhylafax4.2.0-devel-4.2.1-2.2.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
