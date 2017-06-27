#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:044. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14143);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:47:35 $");

  script_cve_id("CVE-2004-2392");
  script_xref(name:"MDKSA", value:"2004:044");

  script_name(english:"Mandrake Linux Security Advisory : libuser (MDKSA-2004:044)");
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
"Steve Grubb discovered a number of problems in the libuser library
that can lead to a crash in applications linked to it, or possibly
write 4GB of garbage to the disk.

The updated packages provide a patched libuser to correct these
problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libuser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libuser-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libuser1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libuser1-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
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
if (rpm_check(release:"MDK10.0", reference:"libuser-0.51.7-9.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"libuser-python-0.51.7-9.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"libuser1-0.51.7-9.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"libuser1-devel-0.51.7-9.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"libuser-0.51-6.1.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"libuser1-0.51-6.1.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"libuser1-devel-0.51-6.1.91mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"libuser-0.51.7-8.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"libuser-python-0.51.7-8.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"libuser1-0.51.7-8.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"libuser1-devel-0.51.7-8.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
