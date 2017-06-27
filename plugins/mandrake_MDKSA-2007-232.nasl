#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:232. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(36221);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:01:21 $");

  script_cve_id("CVE-2006-6058", "CVE-2007-4997");
  script_xref(name:"MDKSA", value:"2007:232");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2007:232)");
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
"Some vulnerabilities were discovered and corrected in the Linux 2.6
kernel :

The minix filesystem code allows local users to cause a denial of
service (hang) via a malformed minix file stream (CVE-2006-6058).

An integer underflow in the Linux kernel prior to 2.6.23 allows remote
attackers to cause a denial of service (crash) via a crafted SKB
length value in a runt IEEE 802.11 frame when the
IEEE80211_STYPE_QOS_DATA flag is set (CVE-2007-4997).

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.22.12-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-2.6.22.12-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-2.6.22.12-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-2.6.22.12-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-2.6.22.12-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-laptop-2.6.22.12-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-laptop-devel-2.6.22.12-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-laptop-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-laptop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-2.6.22.12-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-2.6.22.12-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.22.12-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/28");
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
if (rpm_check(release:"MDK2008.0", reference:"kernel-2.6.22.12-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-desktop-2.6.22.12-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-desktop-devel-2.6.22.12-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-desktop-devel-latest-2.6.22.12-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-desktop-latest-2.6.22.12-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"kernel-desktop586-2.6.22.12-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"kernel-desktop586-devel-2.6.22.12-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"kernel-desktop586-devel-latest-2.6.22.12-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"kernel-desktop586-latest-2.6.22.12-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-doc-2.6.22.12-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-laptop-2.6.22.12-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-laptop-devel-2.6.22.12-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-laptop-devel-latest-2.6.22.12-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-laptop-latest-2.6.22.12-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-server-2.6.22.12-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-server-devel-2.6.22.12-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-server-devel-latest-2.6.22.12-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-server-latest-2.6.22.12-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-source-2.6.22.12-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-source-latest-2.6.22.12-1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
