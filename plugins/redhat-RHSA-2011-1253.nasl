#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1253. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76634);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/03 14:49:09 $");

  script_cve_id("CVE-2010-4243", "CVE-2010-4526", "CVE-2011-1020", "CVE-2011-1021", "CVE-2011-1090", "CVE-2011-1160", "CVE-2011-1478", "CVE-2011-1479", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1576", "CVE-2011-1577", "CVE-2011-1585", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1748", "CVE-2011-1767", "CVE-2011-1768", "CVE-2011-1770", "CVE-2011-1776", "CVE-2011-2022", "CVE-2011-2183", "CVE-2011-2213", "CVE-2011-2484", "CVE-2011-2491", "CVE-2011-2492", "CVE-2011-2495", "CVE-2011-2496", "CVE-2011-2497", "CVE-2011-2517", "CVE-2011-2695");
  script_bugtraq_id(45004, 45661, 46567, 46766, 46866, 47056, 47185, 47296, 47321, 47343, 47381, 47497, 47503, 47534, 47535, 47769, 47796, 47835, 47843, 47852, 47853, 48333, 48383, 48441, 48472, 48538, 48697, 48907, 49141, 49408);
  script_osvdb_id(71271);
  script_xref(name:"RHSA", value:"2011:1253");

  script_name(english:"RHEL 6 : MRG (RHSA-2011:1253)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel-rt packages that fix multiple security issues and
various bugs are now available for Red Hat Enterprise MRG 2.0.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Security fixes :

* A flaw in the SCTP and DCCP implementations could allow a remote
attacker to cause a denial of service. (CVE-2010-4526, CVE-2011-1770,
Important)

* Flaws in the Management Module Support for Message Passing
Technology (MPT) based controllers could allow a local, unprivileged
user to cause a denial of service, an information leak, or escalate
their privileges. (CVE-2011-1494, CVE-2011-1495, Important)

* Flaws in the AGPGART driver, and a flaw in agp_allocate_memory(),
could allow a local user to cause a denial of service or escalate
their privileges. (CVE-2011-1745, CVE-2011-2022, CVE-2011-1746,
Important)

* A flaw in the client-side NLM implementation could allow a local,
unprivileged user to cause a denial of service. (CVE-2011-2491,
Important)

* A flaw in the Bluetooth implementation could allow a remote attacker
to cause a denial of service or escalate their privileges.
(CVE-2011-2497, Important)

* Flaws in the netlink-based wireless configuration interface could
allow a local user, who has the CAP_NET_ADMIN capability, to cause a
denial of service or escalate their privileges on systems that have an
active wireless interface. (CVE-2011-2517, Important)

* The maximum file offset handling for ext4 file systems could allow a
local, unprivileged user to cause a denial of service. (CVE-2011-2695,
Important)

* A local, unprivileged user could allocate large amounts of memory
not visible to the OOM killer, causing a denial of service.
(CVE-2010-4243, Moderate)

* The proc file system could allow a local, unprivileged user to
obtain sensitive information or possibly cause integrity issues.
(CVE-2011-1020, Moderate)

* A local, privileged user could possibly write arbitrary kernel
memory via /sys/kernel/debug/acpi/custom_method. (CVE-2011-1021,
Moderate)

* Inconsistency in the methods for allocating and freeing NFSv4 ACL
data; CVE-2010-4250 fix caused a regression; a flaw in next_pidmap()
and inet_diag_bc_audit(); flaws in the CAN implementation; a race
condition in the memory merging support; a flaw in the taskstats
subsystem; and the way mapping expansions were handled could allow a
local, unprivileged user to cause a denial of service. (CVE-2011-1090,
CVE-2011-1479, CVE-2011-1593, CVE-2011-2213, CVE-2011-1598,
CVE-2011-1748, CVE-2011-2183, CVE-2011-2484, CVE-2011-2496, Moderate)

* A flaw in GRO could result in a denial of service when a malformed
VLAN frame is received. (CVE-2011-1478, Moderate)

* napi_reuse_skb() could be called on VLAN packets allowing an
attacker on the local network to possibly trigger a denial of service.
(CVE-2011-1576, Moderate)

* A denial of service could occur if packets were received while the
ipip or ip_gre module was being loaded. (CVE-2011-1767, CVE-2011-1768,
Moderate)

* Information leaks. (CVE-2011-1160, CVE-2011-2492, CVE-2011-2495,
Low)

* Flaws in the EFI GUID Partition Table implementation could allow a
local attacker to cause a denial of service. (CVE-2011-1577,
CVE-2011-1776, Low)

* While a user has a CIFS share mounted that required successful
authentication, a local, unprivileged user could mount that share
without knowing the correct password if mount.cifs was setuid root.
(CVE-2011-1585, Low)

Red Hat would like to thank Dan Rosenberg for reporting CVE-2011-1770,
CVE-2011-1494, CVE-2011-1495, CVE-2011-2497, and CVE-2011-2213;
Vasiliy Kulikov of Openwall for reporting CVE-2011-1745,
CVE-2011-2022, CVE-2011-1746, CVE-2011-2484, and CVE-2011-2495; Vasily
Averin for reporting CVE-2011-2491; Brad Spengler for reporting
CVE-2010-4243; Kees Cook for reporting CVE-2011-1020; Robert Swiecki
for reporting CVE-2011-1593 and CVE-2011-2496; Oliver Hartkopp for
reporting CVE-2011-1748; Andrea Righi for reporting CVE-2011-2183;
Ryan Sweat for reporting CVE-2011-1478 and CVE-2011-1576; Peter Huewe
for reporting CVE-2011-1160; Marek Kroemeke and Filip Palian for
reporting CVE-2011-2492; and Timo Warns for reporting CVE-2011-1577
and CVE-2011-1776."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4243.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4526.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1479.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1495.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1576.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1577.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1593.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1598.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1746.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1748.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1768.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1770.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2183.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2213.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2492.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2495.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2496.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2497.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2517.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2695.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_MRG/2.0/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1253.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1253";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;

  if (! (rpm_exists(release:"RHEL6", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debug-devel-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-devel-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-rt-doc-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-rt-firmware-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-trace-devel-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-debuginfo-2.6.33.9-rt31.75.el6rt")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-rt-vanilla-devel-2.6.33.9-rt31.75.el6rt")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt / kernel-rt-debug / kernel-rt-debug-debuginfo / etc");
  }
}
