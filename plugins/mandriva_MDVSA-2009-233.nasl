#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:233. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(40980);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2009-2692");
  script_bugtraq_id(36038);
  script_xref(name:"MDVSA", value:"2009:233");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2009:233)");
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
"A vulnerability was discovered and corrected in the Linux 2.6 kernel :

The Linux kernel 2.6.0 through 2.6.30.4, and 2.4.4 through 2.4.37.4,
does not initialize all function pointers for socket operations in
proto_ops structures, which allows local users to trigger a NULL
pointer dereference and gain privileges by using mmap to map page
zero, placing arbitrary code on this page, and then invoking an
unavailable operation, as demonstrated by the sendpage operation on a
PF_PPPOX socket. (CVE-2009-2692)

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel Sendpage Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.24.7-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-2.6.24.7-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-2.6.24.7-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-2.6.24.7-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-2.6.24.7-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-laptop-2.6.24.7-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-laptop-devel-2.6.24.7-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-laptop-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-laptop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-2.6.24.7-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-2.6.24.7-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.24.7-3mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.1", reference:"kernel-2.6.24.7-3mnb-1-1mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-desktop-2.6.24.7-3mnb-1-1mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-desktop-devel-2.6.24.7-3mnb-1-1mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-desktop-devel-latest-2.6.24.7-3mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-desktop-latest-2.6.24.7-3mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"kernel-desktop586-2.6.24.7-3mnb-1-1mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"kernel-desktop586-devel-2.6.24.7-3mnb-1-1mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"kernel-desktop586-devel-latest-2.6.24.7-3mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"kernel-desktop586-latest-2.6.24.7-3mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-doc-2.6.24.7-3mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-laptop-2.6.24.7-3mnb-1-1mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-laptop-devel-2.6.24.7-3mnb-1-1mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-laptop-devel-latest-2.6.24.7-3mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-laptop-latest-2.6.24.7-3mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-server-2.6.24.7-3mnb-1-1mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-server-devel-2.6.24.7-3mnb-1-1mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-server-devel-latest-2.6.24.7-3mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-server-latest-2.6.24.7-3mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-source-2.6.24.7-3mnb-1-1mnb1")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"kernel-source-latest-2.6.24.7-3mnb1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
