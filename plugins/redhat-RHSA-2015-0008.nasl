#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0008. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80388);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/06 15:51:00 $");

  script_cve_id("CVE-2014-7823");
  script_bugtraq_id(71095);
  script_xref(name:"RHSA", value:"2015:0008");

  script_name(english:"RHEL 7 : libvirt (RHSA-2015:0008)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix one security issue and three bugs
are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

It was found that when the VIR_DOMAIN_XML_MIGRATABLE flag was used,
the QEMU driver implementation of the virDomainGetXMLDesc() function
could bypass the restrictions of the VIR_DOMAIN_XML_SECURE flag. A
remote attacker able to establish a read-only connection to libvirtd
could use this flaw to leak certain limited information from the
domain XML data. (CVE-2014-7823)

This issue was discovered by Eric Blake of Red Hat.

This update also fixes the following bugs :

* In Red Hat Enterprise Linux 6, libvirt relies on the QEMU emulator
to supply the error message when an active commit is attempted.
However, with Red Hat Enterprise Linux 7, QEMU added support for an
active commit, but an additional interaction from libvirt to fully
enable active commits is still missing. As a consequence, attempts to
perform an active commit caused libvirt to become unresponsive. With
this update, libvirt has been fixed to detect an active commit by
itself, and now properly declares the feature as unsupported. As a
result, libvirt no longer hangs when an active commit is attempted and
instead produces an error message.

Note that the missing libvirt interaction will be added in Red Hat
Enterprise Linux 7.1, adding full support for active commits.
(BZ#1150379)

* Prior to this update, the libvirt API did not properly check whether
a Discretionary Access Control (DAC) security label is non-NULL before
trying to parse user/group ownership from it. In addition, the DAC
security label of a transient domain that had just finished migrating
to another host is in some cases NULL. As a consequence, when the
virDomainGetBlockInfo API was called on such a domain, the libvirtd
daemon sometimes terminated unexpectedly. With this update, libvirt
properly checks DAC labels before trying to parse them, and libvirtd
thus no longer crashes in the described scenario. (BZ#1171124)

* If a block copy operation was attempted while another block copy was
already in progress to an explicit raw destination, libvirt previously
stopped regarding the destination as raw. As a consequence, if the
qemu.conf file was edited to allow file format probing, triggering the
bug could allow a malicious guest to bypass sVirt protection by making
libvirt regard the file as non-raw. With this update, libvirt has been
fixed to consistently remember when a block copy destination is raw,
and guests can no longer circumvent sVirt protection when the host is
configured to allow format probing. (BZ#1149078)

All libvirt users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, libvirtd will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7823.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0008.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2015:0008";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libvirt-client-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-config-network-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-config-network-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-config-nwfilter-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-interface-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-lxc-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-network-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-nodedev-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-nwfilter-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-secret-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-storage-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-kvm-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-lxc-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-lxc-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libvirt-debuginfo-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libvirt-devel-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-docs-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-docs-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-lock-sanlock-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-login-shell-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-login-shell-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-python-1.1.1-29.el7_0.4")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-python-1.1.1-29.el7_0.4")) flag++;

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
