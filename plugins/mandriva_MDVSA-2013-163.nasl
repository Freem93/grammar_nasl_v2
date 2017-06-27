#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:163. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66342);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/11/25 11:41:41 $");

  script_cve_id("CVE-2013-0242", "CVE-2013-1914");
  script_bugtraq_id(57638, 58839);
  script_xref(name:"MDVSA", value:"2013:163");

  script_name(english:"Mandriva Linux Security Advisory : glibc (MDVSA-2013:163)");
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
"Multiple vulnerabilities has been discovered and corrected in glibc :

Buffer overflow in the extend_buffers function in the regular
expression matcher (posix/regexec.c) in glibc, possibly 2.17 and
earlier, allows context-dependent attackers to cause a denial of
service (memory corruption and crash) via crafted multibyte characters
(CVE-2013-0242).

Stack-based buffer overflow in the getaddrinfo function in
sysdeps/posix/getaddrinfo.c in GNU C Library (aka glibc or libc6) 2.17
and earlier allows remote attackers to cause a denial of service
(crash) via a (1) hostname or (2) IP address that triggers a large
number of domain conversion results (CVE-2013-1914).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"glibc-2.14.1-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"glibc-devel-2.14.1-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"glibc-doc-2.14.1-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"glibc-doc-pdf-2.14.1-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"glibc-i18ndata-2.14.1-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"glibc-profile-2.14.1-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"glibc-static-devel-2.14.1-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"glibc-utils-2.14.1-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"nscd-2.14.1-12.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
