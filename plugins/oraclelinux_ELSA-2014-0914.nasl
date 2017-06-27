#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0914 and 
# Oracle Linux Security Advisory ELSA-2014-0914 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(76741);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/04/27 16:14:42 $");

  script_cve_id("CVE-2014-0179", "CVE-2014-5177");
  script_bugtraq_id(67289);
  script_xref(name:"RHSA", value:"2014:0914");

  script_name(english:"Oracle Linux 7 : libvirt (ELSA-2014-0914)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:0914 :

Updated libvirt packages that fix one security issue and three bugs
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
    value:"https://oss.oracle.com/pipermail/el-errata/2014-July/004289.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-client-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-config-network-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-kvm-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-lxc-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-devel-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-docs-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-lock-sanlock-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-login-shell-1.1.1-29.0.1.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-python-1.1.1-29.0.1.el7_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-daemon / etc");
}
