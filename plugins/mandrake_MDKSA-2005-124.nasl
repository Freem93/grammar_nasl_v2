#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:124. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(19885);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/08/16 19:14:48 $");

  script_cve_id("CVE-2005-1849");
  script_xref(name:"MDKSA", value:"2005:124");

  script_name(english:"Mandrake Linux Security Advisory : zlib (MDKSA-2005:124)");
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
"A previous zlib update (MDKSA-2005:112; CVE-2005-2096) fixed an
overflow flaw in the zlib program. While that update did indeed fix
the reported overflow issue, Markus Oberhumber discovered additional
ways that a specially crafted compressed stream could trigger an
overflow. An attacker could create such a stream that would cause a
linked application to crash if opened by a user.

The updated packages are provided to protect against this flaw. The
Corporate Server 2.1 product is not affected by this vulnerability."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected zlib1 and / or zlib1-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zlib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:zlib1-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"zlib1-1.2.1-2.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"zlib1-devel-1.2.1-2.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"zlib1-1.2.1.1-3.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"zlib1-devel-1.2.1.1-3.2.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"zlib1-1.2.2.2-2.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"zlib1-devel-1.2.2.2-2.2.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
