#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0424. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63933);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2010-1188");
  script_bugtraq_id(39016);
  script_xref(name:"RHSA", value:"2010:0424");

  script_name(english:"RHEL 4 : kernel (RHSA-2010:0424)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and add one
enhancement are now available for Red Hat Enterprise Linux 4.7
Extended Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

* a use-after-free flaw was found in the tcp_rcv_state_process()
function in the Linux kernel TCP/IP protocol suite implementation. If
a system using IPv6 had the IPV6_RECVPKTINFO option set on a listening
socket, a remote attacker could send an IPv6 packet to that system,
causing a kernel panic (denial of service). (CVE-2010-1188, Important)

This update also adds the following enhancement :

* kernel support for the iptables connlimit module. This module can be
used to help mitigate some types of denial of service attacks. Note:
This update alone does not address connlimit support. A future
iptables package update will allow connlimit to work correctly.
(BZ#563222)

Users should upgrade to these updated packages, which contain
backported patches to correct this issue and add this enhancement. The
system must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0424.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL4", sp:"7", reference:"kernel-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", reference:"kernel-devel-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", reference:"kernel-doc-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-hugemem-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-smp-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-smp-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-smp-devel-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-xenU-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-xenU-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-xenU-devel-2.6.9-78.0.31.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-78.0.31.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
