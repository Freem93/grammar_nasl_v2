#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:007. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24623);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:56:40 $");

  script_cve_id("CVE-2006-5379");
  script_xref(name:"MDKSA", value:"2007:007");

  script_name(english:"Mandrake Linux Security Advisory : nvidia (MDKSA-2007:007)");
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
"A vulnerability in the NVIDIA Xorg driver was discovered by Derek
Abdine who found that it did not correctly verify the size of buffers
used to render text glyphs, resulting in a crash of the server when
displaying very long strings of text. If a user was tricked into
viewing a specially crafted series of glyphs, this flaw could be
exploited to run arbitrary code with root privileges.

This vulnerability exists in driver versions 1.0-8762 and 1.0-8774 and
is corrected in 1.0-8776 which is being provided with this update.

The packages can be found in the non-free/updates media."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dkms-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-kernel-2.6.17-5mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-kernel-2.6.17-5mdventerprise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-kernel-2.6.17-5mdvlegacy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", reference:"dkms-nvidia-8776-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"nvidia-8776-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"nvidia-kernel-2.6.17-5mdv-8776-1mdk", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"nvidia-kernel-2.6.17-5mdventerprise-8776-1mdk", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"nvidia-kernel-2.6.17-5mdvlegacy-8776-1mdk", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
