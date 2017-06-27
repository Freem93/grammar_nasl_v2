#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:128. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(15650);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:47:36 $");

  script_cve_id("CVE-2004-0755", "CVE-2004-0983");
  script_xref(name:"MDKSA", value:"2004:128");

  script_name(english:"Mandrake Linux Security Advisory : ruby (MDKSA-2004:128)");
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
"Andres Salomon noticed a problem with the CGI session management in
Ruby. The CGI:Session's FileStore implementations store session
information in an insecure manner by just creating files and ignoring
permission issues (CVE-2004-0755).

The ruby developers have corrected a problem in the ruby CGI module
that can be triggered remotely and cause an inifinite loop on the
server (CVE-2004-0983).

The updated packages are patched to prevent these problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/09");
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
if (rpm_check(release:"MDK10.0", reference:"ruby-1.8.1-1.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"ruby-devel-1.8.1-1.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"ruby-doc-1.8.1-1.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"ruby-tk-1.8.1-1.2.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"ruby-1.8.1-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"ruby-devel-1.8.1-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"ruby-doc-1.8.1-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"ruby-tk-1.8.1-4.2.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"ruby-1.8.0-4.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"ruby-devel-1.8.0-4.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"ruby-doc-1.8.0-4.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"ruby-tk-1.8.0-4.2.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
