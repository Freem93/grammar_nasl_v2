#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:101. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14795);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:47:35 $");

  script_cve_id("CVE-2004-0559");
  script_xref(name:"MDKSA", value:"2004:101");

  script_name(english:"Mandrake Linux Security Advisory : webmin (MDKSA-2004:101)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability in webmin was discovered by Ludwig Nussel. A temporary
directory was used in webmin, however it did not check for the
previous owner of the directory. This could allow an attacker to
create the directory and place dangerous symbolic links inside.

The updated packages are patched to prevent this problem."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:webmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/23");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"webmin-1.121-4.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"webmin-1.121-4.2.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"webmin-1.100-3.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"webmin-1.100-3.2.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
