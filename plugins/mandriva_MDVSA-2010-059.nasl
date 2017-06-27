#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:059. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(45030);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/06/01 00:11:07 $");

  script_cve_id("CVE-2009-3940");
  script_xref(name:"MDVSA", value:"2010:059");

  script_name(english:"Mandriva Linux Security Advisory : virtualbox (MDVSA-2010:059)");
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
"A vulnerability has been found and corrected in virtualbox :

Unspecified vulnerability in Guest Additions in Sun xVM VirtualBox
1.6.x and 2.0.x before 2.0.12, 2.1.x, and 2.2.x, and Sun VirtualBox
before 3.0.10, allows guest OS users to cause a denial of service
(memory consumption) on the guest OS via unknown vectors
(CVE-2009-3940).

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers.

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dkms-vboxadd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dkms-vboxvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dkms-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-2.6.22.19-desktop-2mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-2.6.22.19-desktop586-2mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-2.6.22.19-server-2mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-2.6.27.45-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-2.6.27.45-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-2.6.27.45-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.31.12-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.31.12-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.31.12-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-2.6.22.19-desktop-2mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-2.6.22.19-desktop586-2mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-2.6.22.19-server-2mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-2.6.27.45-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-2.6.27.45-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-2.6.27.45-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-guest-additions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.22.19-desktop-2mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.22.19-desktop586-2mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.22.19-server-2mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.27.45-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.27.45-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.27.45-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.29.6-desktop-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.29.6-desktop586-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.29.6-server-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.31.12-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.31.12-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.31.12-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-driver-input-vboxmouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-driver-video-vboxvideo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"dkms-vboxadd-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"dkms-vboxvfs-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"dkms-virtualbox-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"vboxadd-kernel-2.6.22.19-desktop-2mdv-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"vboxadd-kernel-2.6.22.19-desktop586-2mdv-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"vboxadd-kernel-2.6.22.19-server-2mdv-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"vboxadd-kernel-desktop-latest-1.5.0-1.20100305.6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"vboxadd-kernel-desktop586-latest-1.5.0-1.20100305.6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"vboxadd-kernel-server-latest-1.5.0-1.20100305.6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"vboxvfs-kernel-2.6.22.19-desktop-2mdv-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"vboxvfs-kernel-2.6.22.19-desktop586-2mdv-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"vboxvfs-kernel-2.6.22.19-server-2mdv-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"vboxvfs-kernel-desktop-latest-1.5.0-1.20100305.6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"vboxvfs-kernel-desktop586-latest-1.5.0-1.20100305.6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"vboxvfs-kernel-server-latest-1.5.0-1.20100305.6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"virtualbox-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"virtualbox-guest-additions-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"virtualbox-kernel-2.6.22.19-desktop-2mdv-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"virtualbox-kernel-2.6.22.19-desktop586-2mdv-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"virtualbox-kernel-2.6.22.19-server-2mdv-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"virtualbox-kernel-desktop-latest-1.5.0-1.20100305.6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"virtualbox-kernel-desktop-latest-1.5.0-1.20100309.6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"virtualbox-kernel-desktop586-latest-1.5.0-1.20100305.6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"virtualbox-kernel-server-latest-1.5.0-1.20100305.6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"virtualbox-kernel-server-latest-1.5.0-1.20100309.6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-driver-input-vboxmouse-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-driver-video-vboxvideo-1.5.0-6.2mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"dkms-vboxadd-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"dkms-vboxvfs-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"dkms-virtualbox-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vboxadd-kernel-2.6.27.45-desktop-1mnb-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vboxadd-kernel-2.6.27.45-desktop586-1mnb-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vboxadd-kernel-2.6.27.45-server-1mnb-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vboxadd-kernel-desktop-latest-2.0.2-1.20100309.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"vboxadd-kernel-desktop-latest-2.0.2-1.20100308.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vboxadd-kernel-desktop586-latest-2.0.2-1.20100309.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vboxadd-kernel-server-latest-2.0.2-1.20100309.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"vboxadd-kernel-server-latest-2.0.2-1.20100308.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vboxvfs-kernel-2.6.27.45-desktop-1mnb-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vboxvfs-kernel-2.6.27.45-desktop586-1mnb-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vboxvfs-kernel-2.6.27.45-server-1mnb-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vboxvfs-kernel-desktop-latest-2.0.2-1.20100309.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"vboxvfs-kernel-desktop-latest-2.0.2-1.20100308.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vboxvfs-kernel-desktop586-latest-2.0.2-1.20100309.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vboxvfs-kernel-server-latest-2.0.2-1.20100309.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"vboxvfs-kernel-server-latest-2.0.2-1.20100308.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"virtualbox-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"virtualbox-guest-additions-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"virtualbox-kernel-2.6.27.45-desktop-1mnb-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"virtualbox-kernel-2.6.27.45-desktop586-1mnb-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"virtualbox-kernel-2.6.27.45-server-1mnb-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"virtualbox-kernel-desktop-latest-2.0.2-1.20100309.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"virtualbox-kernel-desktop-latest-2.0.2-1.20100308.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"virtualbox-kernel-desktop586-latest-2.0.2-1.20100309.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"virtualbox-kernel-server-latest-2.0.2-1.20100309.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"virtualbox-kernel-server-latest-2.0.2-1.20100308.2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"x11-driver-input-vboxmouse-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"x11-driver-video-vboxvideo-2.0.2-2.2mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"dkms-vboxadd-2.2.0-4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"dkms-virtualbox-2.2.0-4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vboxadditions-kernel-2.6.29.6-desktop-3mnb-2.2.0-4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vboxadditions-kernel-2.6.29.6-desktop586-3mnb-2.2.0-4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vboxadditions-kernel-2.6.29.6-server-3mnb-2.2.0-4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vboxadditions-kernel-desktop-latest-2.2.0-1.20100308.4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vboxadditions-kernel-desktop586-latest-2.2.0-1.20100308.4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vboxadditions-kernel-server-latest-2.2.0-1.20100308.4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-2.2.0-4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-guest-additions-2.2.0-4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-kernel-2.6.29.6-desktop-3mnb-2.2.0-4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"virtualbox-kernel-2.6.29.6-desktop586-3mnb-2.2.0-4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-kernel-2.6.29.6-server-3mnb-2.2.0-4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-kernel-desktop-latest-2.2.0-1.20100308.4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"virtualbox-kernel-desktop586-latest-2.2.0-1.20100308.4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-kernel-server-latest-2.2.0-1.20100308.4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"x11-driver-input-vboxmouse-2.2.0-4.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"x11-driver-video-vboxvideo-2.2.0-4.1mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"dkms-vboxadd-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dkms-virtualbox-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"vboxadditions-kernel-2.6.31.12-desktop-1mnb-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vboxadditions-kernel-2.6.31.12-desktop586-1mnb-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"vboxadditions-kernel-2.6.31.12-server-1mnb-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vboxadditions-kernel-desktop-latest-3.0.8-1.20100308.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"vboxadditions-kernel-desktop-latest-3.0.8-1.20100309.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vboxadditions-kernel-desktop586-latest-3.0.8-1.20100308.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"vboxadditions-kernel-server-latest-3.0.8-1.20100308.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"vboxadditions-kernel-server-latest-3.0.8-1.20100309.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"virtualbox-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"virtualbox-guest-additions-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"virtualbox-kernel-2.6.31.12-desktop-1mnb-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"virtualbox-kernel-2.6.31.12-desktop586-1mnb-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"virtualbox-kernel-2.6.31.12-server-1mnb-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"virtualbox-kernel-desktop-latest-3.0.8-1.20100308.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"virtualbox-kernel-desktop-latest-3.0.8-1.20100309.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"virtualbox-kernel-desktop586-latest-3.0.8-1.20100308.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"virtualbox-kernel-server-latest-3.0.8-1.20100308.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"virtualbox-kernel-server-latest-3.0.8-1.20100309.1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"x11-driver-input-vboxmouse-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"x11-driver-video-vboxvideo-3.0.8-1.1mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
