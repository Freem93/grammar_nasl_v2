#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2001:071. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13886);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/08/09 10:50:40 $");

  script_cve_id("CVE-2001-0405");
  script_xref(name:"MDKSA", value:"2001:071");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2001:071)");
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
"A security hole was found in the earlier Linux 2.4 kernels dealing
with iptables RELATED connection tracking. The iptables
ip_conntrack_ftp module, which is used for stateful inspection of FTP
traffic, does not validate parameters passed to it in an FTP PORT
command. Due to this flaw, carefully constructed PORT commands could
open arbitrary holes in the firewall. This hole has been fixed, as
well as a number of other bugs for the 2.4 kernel shipped with
Mandrake Linux 8.0

NOTE: This update is *not* meant to be done via MandrakeUpdate! You
must download the necessary RPMs and upgrade manually by following
these steps :

1. Type: rpm -ivh kernel-2.4.7-12.3mdk.i586.rpm 2. Type: mv
kernel-2.4.7-12.3mdk.i586.rpm /tmp 3. Type: rpm -Fvh *.rpm 4. You may
wish to edit /etc/lilo.conf to ensure a new entry is in place. The new
kernel will be the last entry. Change any options you need to change.
5. Type: /sbin/lilo -v

You may then reboot and use the nwe kernel and remove the older kernel
when you are comfortable using the upgraded one."
  );
  # http://www.tempest.com.br/advisories/01-2001.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ad1d1c7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:iptables");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:iptables-ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-pcmcia-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lm_utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lm_utils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"iptables-1.2.2-3.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"iptables-ipv6-1.2.2-3.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-2.4.7-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-doc-2.4.7-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-enterprise-2.4.7-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-headers-2.4.7-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-pcmcia-cs-2.4.7-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-smp-2.4.7-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"kernel-source-2.4.7-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"lm_utils-2.4.7_2.6.0-12.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"lm_utils-devel-2.4.7_2.6.0-12.3mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
