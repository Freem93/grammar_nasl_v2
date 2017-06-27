#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:140. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(15838);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/04/15 10:48:38 $");

  script_cve_id("CVE-2004-1170");
  script_bugtraq_id(11025);
  script_xref(name:"MDKSA", value:"2004:140");

  script_name(english:"Mandrake Linux Security Advisory : a2ps (MDKSA-2004:140)");
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
"The GNU a2ps utility fails to properly sanitize filenames, which can
be abused by a malicious user to execute arbitrary commands with the
privileges of the user running the vulnerable application.

The updated packages have been patched to prevent this problem."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected a2ps, a2ps-devel and / or a2ps-static-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:a2ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:a2ps-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:a2ps-static-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"a2ps-4.13b-5.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"a2ps-devel-4.13b-5.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"a2ps-static-devel-4.13b-5.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"a2ps-4.13b-5.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"a2ps-devel-4.13b-5.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"a2ps-static-devel-4.13b-5.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"a2ps-4.13b-5.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"a2ps-devel-4.13b-5.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"a2ps-static-devel-4.13b-5.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
