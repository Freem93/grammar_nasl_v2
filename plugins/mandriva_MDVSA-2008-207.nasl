#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:207. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(36969);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:06:01 $");

  script_cve_id("CVE-2007-6599");
  script_xref(name:"MDVSA", value:"2008:207");

  script_name(english:"Mandriva Linux Security Advisory : openafs (MDVSA-2008:207)");
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
"A race condition in OpenAFS 1.3.40 through 1.4.5 allowed remote
attackers to cause a denial of service (daemon crash) by
simultaneously acquiring and giving back file callbacks
(CVE-2007-6599).

The updated packages have been patched to prevent this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dkms-libafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openafs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openafs1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenafs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenafs1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openafs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openafs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openafs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openafs-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.1", reference:"dkms-libafs-1.4.2-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64openafs1-1.4.2-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64openafs1-devel-1.4.2-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libopenafs1-1.4.2-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libopenafs1-devel-1.4.2-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"openafs-1.4.2-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"openafs-client-1.4.2-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"openafs-doc-1.4.2-3.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"openafs-server-1.4.2-3.1mdv2007.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.0", reference:"dkms-libafs-1.4.4-8.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64openafs1-1.4.4-8.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64openafs1-devel-1.4.4-8.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libopenafs1-1.4.4-8.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libopenafs1-devel-1.4.4-8.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"openafs-1.4.4-8.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"openafs-client-1.4.4-8.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"openafs-doc-1.4.4-8.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"openafs-server-1.4.4-8.2mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
