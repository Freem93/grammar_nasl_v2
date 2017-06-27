#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0168. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79283);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2006-1168", "CVE-2009-5029", "CVE-2009-5064", "CVE-2010-0830", "CVE-2010-4008", "CVE-2011-0216", "CVE-2011-1083", "CVE-2011-1089", "CVE-2011-1526", "CVE-2011-2716", "CVE-2011-2834", "CVE-2011-3638", "CVE-2011-3905", "CVE-2011-3919", "CVE-2011-4086", "CVE-2011-4109", "CVE-2011-4127", "CVE-2011-4347", "CVE-2011-4576", "CVE-2011-4619", "CVE-2012-0028", "CVE-2012-0029", "CVE-2012-0207");
  script_bugtraq_id(51281, 51343, 51642);
  script_xref(name:"RHSA", value:"2012:0168");

  script_name(english:"RHEL 5 : rhev-hypervisor5 (RHSA-2012:0168)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated rhev-hypervisor5 package that fixes several security issues
and various bugs is now available.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The rhev-hypervisor5 package provides a Red Hat Enterprise
Virtualization Hypervisor ISO disk image. The Red Hat Enterprise
Virtualization Hypervisor is a dedicated Kernel-based Virtual Machine
(KVM) hypervisor. It includes everything necessary to run and manage
virtual machines: A subset of the Red Hat Enterprise Linux operating
environment and the Red Hat Enterprise Virtualization Agent.

Note: Red Hat Enterprise Virtualization Hypervisor is only available
for the Intel 64 and AMD64 architectures with virtualization
extensions.

A heap overflow flaw was found in the way QEMU-KVM emulated the e1000
network interface card. A privileged guest user in a virtual machine
whose network interface is configured to use the e1000 emulated driver
could use this flaw to crash the host or, possibly, escalate their
privileges on the host. (CVE-2012-0029)

A divide-by-zero flaw was found in the Linux kernel's
igmp_heard_query() function. An attacker able to send certain IGMP
(Internet Group Management Protocol) packets to a target system could
use this flaw to cause a denial of service. (CVE-2012-0207)

A double free flaw was discovered in the policy checking code in
OpenSSL. A remote attacker could use this flaw to crash an application
that uses OpenSSL by providing an X.509 certificate that has specially
crafted policy extension data. (CVE-2011-4109)

An information leak flaw was found in the SSL 3.0 protocol
implementation in OpenSSL. Incorrect initialization of SSL record
padding bytes could cause an SSL client or server to send a limited
amount of possibly sensitive data to its SSL peer via the encrypted
connection. (CVE-2011-4576)

It was discovered that OpenSSL did not limit the number of TLS/SSL
handshake restarts required to support Server Gated Cryptography. A
remote attacker could use this flaw to make a TLS/SSL server using
OpenSSL consume an excessive amount of CPU by continuously restarting
the handshake. (CVE-2011-4619)

Red Hat would like to thank Nicolae Mogoreanu for reporting
CVE-2012-0029, and Simon McVittie for reporting CVE-2012-0207.

This updated package provides updated components that include fixes
for various security issues. These issues have no security impact on
Red Hat Enterprise Virtualization Hypervisor itself, however. The
security fixes included in this update address the following CVE
numbers :

CVE-2006-1168 and CVE-2011-2716 (busybox issues)

CVE-2009-5029, CVE-2009-5064, CVE-2010-0830 and CVE-2011-1089 (glibc
issues)

CVE-2011-1083, CVE-2011-3638, CVE-2011-4086, CVE-2011-4127 and
CVE-2012-0028 (kernel issues)

CVE-2011-1526 (krb5 issue)

CVE-2011-4347 (kvm issue)

CVE-2010-4008, CVE-2011-0216, CVE-2011-2834, CVE-2011-3905,
CVE-2011-3919 and CVE-2011-1944 (libxml2 issues)

CVE-2011-1749 (nfs-utils issue)

CVE-2011-4108 (openssl issue)

CVE-2011-0010 (sudo issue)

CVE-2011-1675 and CVE-2011-1677 (util-linux issues)

CVE-2010-0424 (vixie-cron issue)

This updated rhev-hypervisor5 package fixes various bugs.
Documentation of these changes will be available shortly in the
Technical Notes document :

https://docs.redhat.com/docs/en-US/
Red_Hat_Enterprise_Virtualization_for_Servers/2.2/html/Technical_Notes
/ index.html

Users of Red Hat Enterprise Virtualization Hypervisor are advised to
upgrade to this updated package, which fixes these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4109.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4576.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4619.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0207.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.redhat.com/docs/en-US/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0168.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected rhev-hypervisor5 and / or rhev-hypervisor5-tools
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor5-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/17");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0168";
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
  if (rpm_check(release:"RHEL5", reference:"rhev-hypervisor5-5.8-20120202.0.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhev-hypervisor5-tools-5.8-20120202.0.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhev-hypervisor5 / rhev-hypervisor5-tools");
  }
}
