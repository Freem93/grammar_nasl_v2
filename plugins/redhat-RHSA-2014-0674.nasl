#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0674. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79029);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 15:40:57 $");

  script_cve_id("CVE-2013-4148", "CVE-2013-4151", "CVE-2013-4535", "CVE-2013-4536", "CVE-2013-4541", "CVE-2013-4542", "CVE-2013-6399", "CVE-2014-0142", "CVE-2014-0143", "CVE-2014-0144", "CVE-2014-0145", "CVE-2014-0146", "CVE-2014-0147", "CVE-2014-0148", "CVE-2014-0150", "CVE-2014-0182", "CVE-2014-2894", "CVE-2014-3461");
  script_xref(name:"RHSA", value:"2014:0674");

  script_name(english:"RHEL 6 : rhev-hypervisor6 3.4.0 (RHSA-2014:0674)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rhev-hypervisor6 packages that fix multiple security issues,
several bugs, and add various enhancements are now available.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The rhev-hypervisor6 package provides a Red Hat Enterprise
Virtualization Hypervisor ISO disk image. The Red Hat Enterprise
Virtualization Hypervisor is a dedicated Kernel-based Virtual Machine
(KVM) hypervisor.

Multiple integer overflow, input validation, logic error, and buffer
overflow flaws were discovered in various QEMU block drivers. An
attacker able to modify a disk image file loaded by a guest could use
these flaws to crash the guest, or corrupt QEMU process memory on the
host, potentially resulting in arbitrary code execution on the host
with the privileges of the QEMU process. (CVE-2014-0143,
CVE-2014-0144, CVE-2014-0145, CVE-2014-0147)

Multiple buffer overflow, input validation, and out-of-bounds write
flaws were found in the way the virtio, virtio-net, virtio-scsi, and
usb drivers of QEMU handled state loading after migration. A user able
to alter the savevm data (either on the disk or over the wire during
migration) could use either of these flaws to corrupt QEMU process
memory on the (destination) host, which could potentially result in
arbitrary code execution on the host with the privileges of the QEMU
process. (CVE-2013-4148, CVE-2013-4151, CVE-2013-4535, CVE-2013-4536,
CVE-2013-4541, CVE-2013-4542, CVE-2013-6399, CVE-2014-0182,
CVE-2014-3461)

An out-of-bounds memory access flaw was found in the way QEMU's IDE
device driver handled the execution of SMART EXECUTE OFFLINE commands.
A privileged guest user could use this flaw to corrupt QEMU process
memory on the host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process.
(CVE-2014-2894)

A buffer overflow flaw was found in the way the
virtio_net_handle_mac() function of QEMU processed guest requests to
update the table of MAC addresses. A privileged guest user could use
this flaw to corrupt QEMU process memory on the host, potentially
resulting in arbitrary code execution on the host with the privileges
of the QEMU process. (CVE-2014-0150)

A divide-by-zero flaw was found in the seek_to_sector() function of
the parallels block driver in QEMU. An attacker able to modify a disk
image file loaded by a guest could use this flaw to crash the guest.
(CVE-2014-0142)

A NULL pointer dereference flaw was found in the QCOW2 block driver in
QEMU. An attacker able to modify a disk image file loaded by a guest
could use this flaw to crash the guest. (CVE-2014-0146)

It was found that the block driver for Hyper-V VHDX images did not
correctly calculate BAT (Block Allocation Table) entries due to a
missing bounds check. An attacker able to modify a disk image file
loaded by a guest could use this flaw to crash the guest.
(CVE-2014-0148)

The CVE-2014-0143 issues were discovered by Kevin Wolf and Stefan
Hajnoczi of Red Hat, the CVE-2014-0144 issues were discovered by Fam
Zheng, Jeff Cody, Kevin Wolf, and Stefan Hajnoczi of Red Hat, the
CVE-2014-0145 issues were discovered by Stefan Hajnoczi of Red Hat,
the CVE-2014-0150 issue was discovered by Michael S. Tsirkin of Red
Hat, the CVE-2014-0142, CVE-2014-0146, and CVE-2014-0147 issues were
discovered by Kevin Wolf of Red Hat, the CVE-2014-0148 issue was
discovered by Jeff Cody of Red Hat, and the CVE-2013-4148,
CVE-2013-4151, CVE-2013-4535, CVE-2013-4536, CVE-2013-4541,
CVE-2013-4542, CVE-2013-6399, CVE-2014-0182, and CVE-2014-3461 issues
were discovered by Michael S. Tsirkin of Red Hat, Anthony Liguori, and
Michael Roth.

Other changes to the rhev-hypervisor6 component :

* The most recent builds of rhn-virtualization-common and
rhn-virtualization-host are included in version 3.4.0. (BZ#1095812)

All users of qemu-kvm-rhev are advised to upgrade to these updated
packages, which contain backported patches to correct these issues and
add these enhancements. After installing this update, shut down all
running virtual machines. Once all virtual machines have shut down,
start them again for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4148.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4151.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4535.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4536.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4541.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4542.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6399.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0142.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0143.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0144.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0145.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0146.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0147.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0148.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0150.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2894.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0674.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rhev-hypervisor6 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/09");
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
  rhsa = "RHSA-2014:0674";
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
  if (rpm_check(release:"RHEL6", reference:"rhev-hypervisor6-6.5-20140603.2.el6ev")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhev-hypervisor6");
  }
}
