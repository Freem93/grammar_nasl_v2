#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2577 and 
# Oracle Linux Security Advisory ELSA-2016-2577 respectively.
#

include("compat.inc");

if (description)
{
  script_id(94700);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/12/07 21:08:17 $");

  script_cve_id("CVE-2015-5160", "CVE-2015-5313", "CVE-2016-5008");
  script_osvdb_id(126302, 131656, 140745);
  script_xref(name:"RHSA", value:"2016:2577");

  script_name(english:"Oracle Linux 7 : libvirt (ELSA-2016-2577)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2577 :

An update for libvirt is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libvirt library contains a C API for managing and interacting with
the virtualization capabilities of Linux and other operating systems.
In addition, libvirt provides tools for remote management of
virtualized systems.

The following packages have been upgraded to a newer upstream version:
libvirt (2.0.0). (BZ#830971, BZ#1286679)

Security Fix(es) :

* It was found that the libvirt daemon, when using RBD (RADOS Block
Device), leaked private credentials to the process list. A local
attacker could use this flaw to perform certain privileged operations
within the cluster. (CVE-2015-5160)

* A path-traversal flaw was found in the way the libvirt daemon
handled filesystem names for storage volumes. A libvirt user with
privileges to create storage volumes and without privileges to create
and modify domains could possibly use this flaw to escalate their
privileges. (CVE-2015-5313)

* It was found that setting a VNC password to an empty string in
libvirt did not disable all access to the VNC server as documented,
instead it allowed access with no authentication required. An attacker
could use this flaw to access a VNC server with an empty VNC password
without any authentication. (CVE-2016-5008)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006468.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-client-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-config-network-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-kvm-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-lxc-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-devel-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-docs-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-lock-sanlock-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-login-shell-2.0.0-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-nss-2.0.0-10.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-daemon / etc");
}
