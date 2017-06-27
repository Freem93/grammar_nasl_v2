#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:057. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(81940);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/19 15:24:54 $");

  script_cve_id("CVE-2013-7421", "CVE-2014-8160", "CVE-2014-9644");
  script_bugtraq_id(72061, 72320, 72322);
  script_xref(name:"MDVSA", value:"2015:057");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2015:057)");
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
"Multiple vulnerabilities has been found and corrected in the Linux
kernel :

The Crypto API in the Linux kernel before 3.18.5 allows local users to
load arbitrary kernel modules via a bind system call for an AF_ALG
socket with a parenthesized module template expression in the
salg_name field, as demonstrated by the vfat(aes) expression, a
different vulnerability than CVE-2013-7421 (CVE-2014-9644).

net/netfilter/nf_conntrack_proto_generic.c in the Linux kernel before
3.18 generates incorrect conntrack entries during handling of certain
iptables rule sets for the SCTP, DCCP, GRE, and UDP-Lite protocols,
which allows remote attackers to bypass intended access restrictions
via packets with disallowed port numbers (CVE-2014-8160).

The Crypto API in the Linux kernel before 3.18.5 allows local users to
load arbitrary kernel modules via a bind system call for an AF_ALG
socket with a module name in the salg_name field, a different
vulnerability than CVE-2014-9644 (CVE-2013-7421).

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"cpupower-3.4.106-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-firmware-3.4.106-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-headers-3.4.106-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-3.4.106-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-devel-3.4.106-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-source-3.4.106-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower-devel-3.4.106-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower0-3.4.106-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perf-3.4.106-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
