#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2001:007. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61881);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/22 11:11:55 $");

  script_cve_id("CVE-2001-0120");
  script_xref(name:"MDKSA", value:"2001:007");

  script_name(english:"Mandrake Linux Security Advisory : shadow-utils (MDKSA-2001:007)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"WireX discovered a potential temporary file race condition in the
useradd program contained in the shadow-utils package. The useradd
program creates it's temporary files in the protected directory
/etc/default, but if this directory is changed to world-writable, a
problem could occur. This update corrects the problem."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected shadow-utils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:shadow-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:6.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"shadow-utils-980403-7.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"shadow-utils-980403-7.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"shadow-utils-19990827-4.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"shadow-utils-19990827-4.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"shadow-utils-19990827-8.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
