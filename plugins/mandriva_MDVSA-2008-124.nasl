#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:124. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(37421);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/03/19 14:49:27 $");

  script_cve_id("CVE-2008-1686");
  script_bugtraq_id(28665);
  script_xref(name:"MDVSA", value:"2008:124");

  script_name(english:"Mandriva Linux Security Advisory : xine-lib (MDVSA-2008:124)");
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
"A vulnerability in the Speex library was found where it did not
properly validate input values read from the Speex files headers. An
attacker could create a malicious Speex file that would crash an
application or potentially allow the execution of arbitrary code with
the privileges of the application calling the Speex library
(CVE-2008-1686).

Xine-lib is similarly affected by this issue.

As well, the previous version of xine as provided in Mandriva Linux
2008.1 would crash when playing matroska files, and a regression was
introduced that prevented Amarok from playing m4a files.

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xine-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xine1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxine-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxine1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-caca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-dxr3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-esd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-pulse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-smb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-wavpack");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64xine-devel-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64xine1-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libxine-devel-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libxine1-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xine-aa-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xine-caca-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xine-dxr3-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xine-esd-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xine-flac-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xine-gnomevfs-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xine-image-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xine-jack-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xine-plugins-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xine-pulse-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xine-sdl-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"xine-smb-1.1.8-4.6mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64xine-devel-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64xine1-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libxine-devel-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libxine1-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-aa-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-caca-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-dxr3-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-esd-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-flac-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-gnomevfs-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-image-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-jack-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-plugins-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-pulse-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-sdl-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-smb-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-wavpack-1.1.11.1-4.1mdv2008.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
