#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1352. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78023);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/06 15:50:59 $");

  script_cve_id("CVE-2014-3633", "CVE-2014-3657");
  script_bugtraq_id(70186, 70210);
  script_xref(name:"RHSA", value:"2014:1352");

  script_name(english:"RHEL 7 : libvirt (RHSA-2014:1352)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix two security issues and one bug are
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

An out-of-bounds read flaw was found in the way libvirt's
qemuDomainGetBlockIoTune() function looked up the disk index in a
non-persistent (live) disk configuration while a persistent disk
configuration was being indexed. A remote attacker able to establish a
read-only connection to libvirtd could use this flaw to crash libvirtd
or, potentially, leak memory from the libvirtd process.
(CVE-2014-3633)

A denial of service flaw was found in the way libvirt's
virConnectListAllDomains() function computed the number of used
domains. A remote attacker able to establish a read-only connection to
libvirtd could use this flaw to make any domain operations within
libvirt unresponsive. (CVE-2014-3657)

The CVE-2014-3633 issue was discovered by Luyao Huang of Red Hat.

This update also fixes the following bug :

* Prior to this update, libvirt was setting the cpuset.mems parameter
for domains with numatune/memory[nodeset] prior to starting them. As a
consequence, domains with such a nodeset, which excluded the NUMA node
with DMA and DMA32 zones (found in /proc/zoneinfo), could not be
started due to failed KVM initialization. With this update, libvirt
sets the cpuset.mems parameter after the initialization, and domains
with any nodeset (in /numatune/memory) can be started without an
error. (BZ#1135871)

All libvirt users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, libvirtd will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3633.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3657.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1352.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1352";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libvirt-client-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-config-network-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-config-network-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-config-nwfilter-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-interface-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-lxc-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-network-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-nodedev-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-nwfilter-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-secret-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-storage-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-kvm-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-lxc-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-lxc-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libvirt-debuginfo-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libvirt-devel-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-docs-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-docs-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-lock-sanlock-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-login-shell-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-login-shell-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-python-1.1.1-29.el7_0.3")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-python-1.1.1-29.el7_0.3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-daemon / etc");
  }
}
