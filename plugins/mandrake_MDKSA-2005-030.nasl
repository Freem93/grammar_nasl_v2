#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:030. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(16359);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:56 $");

  script_cve_id("CVE-2005-0077");
  script_xref(name:"MDKSA", value:"2005:030");

  script_name(english:"Mandrake Linux Security Advisory : perl-DBI (MDKSA-2005:030)");
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
"Javier Fernandez-Sanguino Pena disovered the perl5 DBI library created
a temporary PID file in an insecure manner, which could be exploited
by a malicious user to overwrite arbitrary files owned by the user
executing the parts of the library.

The updated packages have been patched to prevent these problems."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected perl-DBI, perl-DBI-ProfileDumper-Apache and / or
perl-DBI-proxy packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-DBI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-DBI-ProfileDumper-Apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-DBI-proxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"perl-DBI-1.40-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"perl-DBI-ProfileDumper-Apache-1.40-2.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"perl-DBI-proxy-1.40-2.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"perl-DBI-1.43-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"perl-DBI-ProfileDumper-Apache-1.43-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"perl-DBI-proxy-1.43-2.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"perl-DBI-1.38-1.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"perl-DBI-ProfileDumper-Apache-1.38-1.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"perl-DBI-proxy-1.38-1.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
