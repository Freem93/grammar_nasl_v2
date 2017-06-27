#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1527. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78979);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2010-5107", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-4238", "CVE-2013-4344");
  script_bugtraq_id(58162, 61738, 62042, 62043, 62049, 62773);
  script_osvdb_id(90007, 96215, 96766, 96767, 96775, 98028);
  script_xref(name:"RHSA", value:"2013:1527");

  script_name(english:"RHEL 6 : rhev-hypervisor6 (RHSA-2013:1527)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated rhev-hypervisor6 package that fixes multiple security
issues and one bug is now available.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The rhev-hypervisor6 package provides a Red Hat Enterprise
Virtualization Hypervisor ISO disk image. The Red Hat Enterprise
Virtualization Hypervisor is a dedicated Kernel-based Virtual Machine
(KVM) hypervisor. It includes everything necessary to run and manage
virtual machines: a subset of the Red Hat Enterprise Linux operating
environment and the Red Hat Enterprise Virtualization Agent.

Note: Red Hat Enterprise Virtualization Hypervisor is only available
for the Intel 64 and AMD64 architectures with virtualization
extensions.

Upgrade Note: If you upgrade the Red Hat Enterprise Virtualization
Hypervisor through the 3.2 Manager administration portal, the Host may
appear with the status of 'Install Failed'. If this happens, place the
host into maintenance mode, then activate it again to get the host
back to an 'Up' state.

A buffer overflow flaw was found in the way QEMU processed the SCSI
'REPORT LUNS' command when more than 256 LUNs were specified for a
single SCSI target. A privileged guest user could use this flaw to
corrupt QEMU process memory on the host, which could potentially
result in arbitrary code execution on the host with the privileges of
the QEMU process. (CVE-2013-4344)

Multiple flaws were found in the way Linux kernel handled HID (Human
Interface Device) reports. An attacker with physical access to the
system could use this flaw to crash the system or, potentially,
escalate their privileges on the system. (CVE-2013-2888,
CVE-2013-2889, CVE-2013-2892)

A flaw was found in the way the Python SSL module handled X.509
certificate fields that contain a NULL byte. An attacker could
potentially exploit this flaw to conduct man-in-the-middle attacks to
spoof SSL servers. Note that to exploit this issue, an attacker would
need to obtain a carefully crafted certificate signed by an authority
that the client trusts. (CVE-2013-4238)

The default OpenSSH configuration made it easy for remote attackers to
exhaust unauthorized connection slots and prevent other users from
being able to log in to a system. This flaw has been addressed by
enabling random early connection drops by setting MaxStartups to
10:30:100 by default. For more information, refer to the
sshd_config(5) man page. (CVE-2010-5107)

The CVE-2013-4344 issue was discovered by Asias He of Red Hat.

This updated package provides updated components that include fixes
for various security issues. These issues have no security impact on
Red Hat Enterprise Virtualization Hypervisor itself, however. The
security fixes included in this update address the following CVE
numbers :

CVE-2012-0786 and CVE-2012-0787 (augeas issues)

CVE-2013-1813 (busybox issue)

CVE-2013-0221, CVE-2013-0222, and CVE-2013-0223 (coreutils issues)

CVE-2012-4453 (dracut issue)

CVE-2013-4332, CVE-2013-0242, and CVE-2013-1914 (glibc issues)

CVE-2013-4387, CVE-2013-0343, CVE-2013-4345, CVE-2013-4591,
CVE-2013-4592, CVE-2012-6542, CVE-2013-3231, CVE-2013-1929,
CVE-2012-6545, CVE-2013-1928, CVE-2013-2164, CVE-2013-2234, and
CVE-2013-2851 (kernel issues)

CVE-2013-4242 (libgcrypt issue)

CVE-2013-4419 (libguestfs issue)

CVE-2013-1775, CVE-2013-2776, and CVE-2013-2777 (sudo issues)

This update also fixes the following bug :

* A previous version of the rhev-hypervisor6 package did not contain
the latest vhostmd package, which provides a 'metrics communication
channel' between a host and its hosted virtual machines, allowing
limited introspection of host resource usage from within virtual
machines. This has been fixed, and rhev-hypervisor6 now includes the
latest vhostmd package. (BZ#1026703)

This update also contains the fixes from the following errata :

* ovirt-node: https://rhn.redhat.com/errata/RHBA-2013-1528.html

Users of the Red Hat Enterprise Virtualization Hypervisor are advised
to upgrade to this updated package, which corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-5107.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2888.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2889.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2892.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4238.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4344.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHBA-2013-1528.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64c6b598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1527.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b506c4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rhev-hypervisor6 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
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
  rhsa = "RHSA-2013:1527";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL6", reference:"rhev-hypervisor6-6.5-20131115.0.3.2.el6_5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhev-hypervisor6");
  }
}
