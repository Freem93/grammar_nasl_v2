#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0914. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76904);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2014-0179", "CVE-2014-5177");
  script_xref(name:"RHSA", value:"2014:0914");

  script_name(english:"RHEL 7 : libvirt (RHSA-2014:0914)");
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

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

It was found that libvirt passes the XML_PARSE_NOENT flag when parsing
XML documents using the libxml2 library, in which case all XML
entities in the parsed documents are expanded. A user able to force
libvirtd to parse an XML document with an entity pointing to a file
could use this flaw to read the contents of that file; parsing an XML
document with an entity pointing to a special file that blocks on read
access could cause libvirtd to hang indefinitely, resulting in a
denial of service on the system. (CVE-2014-0179)

Red Hat would like to thank the upstream Libvirt project for reporting
this issue. Upstream acknowledges Daniel P. Berrange and Richard Jones
as the original reporters.

This update also fixes the following bugs :

* A previous update of the libvirt package introduced an error; a
SIG_SETMASK argument was incorrectly replaced by a SIG_BLOCK argument
after the poll() system call. Consequently, the SIGCHLD signal could
be permanently blocked, which caused signal masks to not return to
their original values and defunct processes to be generated. With this
update, the original signal masks are restored and defunct processes
are no longer generated. (BZ#1112689)

* An attempt to start a domain that did not exist caused network
filters to be locked for read-only access. As a consequence, when
trying to gain read-write access, a deadlock occurred. This update
applies a patch to fix this bug and an attempt to start a non-existent
domain no longer causes a deadlock in the described scenario.
(BZ#1112690)

* Previously, the libvirtd daemon was binding only to addresses that
were configured on certain network interfaces. When libvirtd started
before the IPv4 addresses had been configured, libvirtd listened only
on the IPv6 addresses. The daemon has been modified to not require an
address to be configured when binding to a wildcard address, such as
'0.0.0.0' or '::'. As a result, libvirtd binds to both IPv4 and IPv6
addresses as expected. (BZ#1112692)

Users of libvirt are advised to upgrade to these updated packages,
which fix these bugs. After installing the updated packages, libvirtd
will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0179.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-5177.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0914.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/30");
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
  rhsa = "RHSA-2014:0914";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libvirt-client-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-config-network-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-config-network-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-config-nwfilter-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-interface-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-lxc-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-network-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-nodedev-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-nwfilter-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-secret-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-driver-storage-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-kvm-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-daemon-lxc-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-daemon-lxc-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libvirt-debuginfo-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libvirt-devel-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-docs-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-docs-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-lock-sanlock-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-login-shell-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-login-shell-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libvirt-python-1.1.1-29.el7_0.1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libvirt-python-1.1.1-29.el7_0.1")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
