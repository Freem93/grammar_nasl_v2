#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0579. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78950);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2012-3411", "CVE-2012-4542", "CVE-2013-0311");
  script_bugtraq_id(54353, 58053, 58088);
  script_xref(name:"RHSA", value:"2013:0579");

  script_name(english:"RHEL 6 : rhev-hypervisor6 (RHSA-2013:0579)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated rhev-hypervisor6 package that fixes three security issues,
various bugs, and adds an enhancement is now available.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The rhev-hypervisor6 package provides a Red Hat Enterprise
Virtualization Hypervisor ISO disk image. The Red Hat Enterprise
Virtualization Hypervisor is a dedicated Kernel-based Virtual Machine
(KVM) hypervisor. It includes everything necessary to run and manage
virtual machines: A subset of the Red Hat Enterprise Linux operating
environment and the Red Hat Enterprise Virtualization Agent.

Note: Red Hat Enterprise Virtualization Hypervisor is only available
for the Intel 64 and AMD64 architectures with virtualization
extensions.

A flaw was found in the way the vhost kernel module handled
descriptors that spanned multiple regions. A privileged guest user
could use this flaw to crash the host or, potentially, escalate their
privileges on the host. (CVE-2013-0311)

It was found that the default SCSI command filter does not accommodate
commands that overlap across device classes. A privileged guest user
could potentially use this flaw to write arbitrary data to a LUN that
is passed-through as read-only. (CVE-2012-4542)

It was discovered that dnsmasq, when used in combination with certain
libvirtd configurations, could incorrectly process network packets
from network interfaces that were intended to be prohibited. A remote,
unauthenticated attacker could exploit this flaw to cause a denial of
service via DNS amplification attacks. (CVE-2012-3411)

The CVE-2012-4542 issue was discovered by Paolo Bonzini of Red Hat.

This updated package provides updated components that include fixes
for several security issues. These issues had no security impact on
Red Hat Enterprise Virtualization Hypervisor itself, however. The
security fixes included in this update address the following CVE
numbers :

CVE-2012-3955 (dhcp issue)

CVE-2011-4355 (gdb issue)

CVE-2012-4508, CVE-2013-0190, CVE-2013-0309, and CVE-2013-0310 (kernel
issues)

CVE-2012-5536 (openssh issue)

CVE-2011-3148 and CVE-2011-3149 (pam issues)

CVE-2013-0157 (util-linux-ng issue)

This updated Red Hat Enterprise Virtualization Hypervisor package also
fixes the following bugs :

* Previously, the Administration Portal would always display the
option to upgrade the Red Hat Enterprise Virtualization Hypervisor ISO
regardless of whether or not the selected host was up-to-date. Now,
the VDSM version compatibility is considered and the upgrade message
only displays if there is an upgrade relevant to the host available.
(BZ#853092)

* An out of date version of libvirt was included in the Red Hat
Enterprise Virtualization Hypervisor 6.4 package. As a result, virtual
machines with supported CPU models were not being properly parsed by
libvirt and failed to start. A more recent version of libvirt has been
included in this updated hypervisor package. Virtual machines now
start normally. (BZ#895078)

As well, this update adds the following enhancement :

* Hypervisor packages now take advantage of the installonlypkg
function provided by yum. This allows for multiple versions of the
hypervisor package to be installed on a system concurrently without
making changes to the yum configuration as was previously required.
(BZ#863579)

This update includes the ovirt-node build from RHBA-2013:0556 :

https://rhn.redhat.com/errata/RHBA-2013-0556.html

Users of the Red Hat Enterprise Virtualization Hypervisor are advised
to upgrade to this updated package, which fixes these issues and adds
this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3411.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4542.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0311.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHBA-2013-0556.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/knowledge/articles/11258"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?faae67f0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0579.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?879a0985"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rhev-hypervisor6 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/28");
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
  rhsa = "RHSA-2013:0579";
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
  if (rpm_check(release:"RHEL6", reference:"rhev-hypervisor6-6.4-20130221.0.el6")) flag++;

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
