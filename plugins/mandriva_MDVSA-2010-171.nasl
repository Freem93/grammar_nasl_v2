#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:171. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(49117);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/12/18 14:26:56 $");

  script_cve_id("CVE-2010-2526");
  script_bugtraq_id(42033);
  script_xref(name:"MDVSA", value:"2010:171");

  script_name(english:"Mandriva Linux Security Advisory : lvm2 (MDVSA-2010:171)");
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
"A vulnerability has been found and corrected in lvm2 :

The cluster logical volume manager daemon (clvmd) in lvm2-cluster in
LVM2 before 2.02.72, as used in Red Hat Global File System (GFS) and
other products, does not verify client credentials upon a socket
connection, which allows local users to cause a denial of service
(daemon exit or logical-volume change) or possibly have unspecified
other impact via crafted control commands (CVE-2010-2526).

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:clvmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cmirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dmsetup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64devmapper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64devmapper-event-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64devmapper-event1.02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64devmapper1.02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64lvm2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64lvm2app2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64lvm2cmd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64lvm2cmd2.02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdevmapper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdevmapper-event-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdevmapper-event1.02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdevmapper1.02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:liblvm2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:liblvm2app2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:liblvm2cmd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:liblvm2cmd2.02");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lvm2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.1", reference:"clvmd-2.02.33-8.1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lvm2-2.02.33-8.1mnb2")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"clvmd-2.02.53-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dmsetup-1.02.38-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64devmapper-devel-1.02.38-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64devmapper-event-devel-1.02.38-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64devmapper-event1.02-1.02.38-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64devmapper1.02-1.02.38-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64lvm2cmd-devel-2.02.53-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64lvm2cmd2.02-2.02.53-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libdevmapper-devel-1.02.38-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libdevmapper-event-devel-1.02.38-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libdevmapper-event1.02-1.02.38-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libdevmapper1.02-1.02.38-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"liblvm2cmd-devel-2.02.53-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"liblvm2cmd2.02-2.02.53-9.2mnb2")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"lvm2-2.02.53-9.2mnb2")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"clvmd-2.02.61-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"cmirror-2.02.61-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dmsetup-1.02.44-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64devmapper-devel-1.02.44-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64devmapper-event-devel-1.02.44-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64devmapper-event1.02-1.02.44-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64devmapper1.02-1.02.44-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64lvm2-devel-2.02.61-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64lvm2app2.1-2.02.61-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64lvm2cmd-devel-2.02.61-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64lvm2cmd2.02-2.02.61-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libdevmapper-devel-1.02.44-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libdevmapper-event-devel-1.02.44-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libdevmapper-event1.02-1.02.44-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libdevmapper1.02-1.02.44-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"liblvm2-devel-2.02.61-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"liblvm2app2.1-2.02.61-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"liblvm2cmd-devel-2.02.61-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"liblvm2cmd2.02-2.02.61-5.1mnb2")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"lvm2-2.02.61-5.1mnb2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
