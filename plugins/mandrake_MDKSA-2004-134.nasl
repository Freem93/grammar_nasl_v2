#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:134. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(15739);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:47:36 $");

  script_cve_id("CVE-2004-0940");
  script_xref(name:"MDKSA", value:"2004:134");

  script_name(english:"Mandrake Linux Security Advisory : apache (MDKSA-2004:134)");
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
"A possible buffer overflow exists in the get_tag() function of
mod_include, and if SSI (Server Side Includes) are enabled, a local
attacker may be able to run arbitrary code with the rights of an httpd
child process. This could be done with a special HTML document using
malformed SSI.

The updated packages have been patched to prevent this problem."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/17");
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
if (rpm_check(release:"MDK10.0", reference:"apache-1.3.29-1.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache-devel-1.3.29-1.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache-modules-1.3.29-1.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache-source-1.3.29-1.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"apache-1.3.31-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache-devel-1.3.31-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache-modules-1.3.31-7.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache-source-1.3.31-7.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"apache-1.3.28-3.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache-devel-1.3.28-3.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache-modules-1.3.28-3.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache-source-1.3.28-3.4.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
