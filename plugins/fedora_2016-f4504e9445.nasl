#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-f4504e9445.
#

include("compat.inc");

if (description)
{
  script_id(90045);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/18 17:03:08 $");

  script_cve_id("CVE-2015-8613", "CVE-2015-8817", "CVE-2015-8818", "CVE-2016-1714", "CVE-2016-1922", "CVE-2016-1981", "CVE-2016-2198", "CVE-2016-2391", "CVE-2016-2392", "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2857", "CVE-2016-2858");
  script_xref(name:"FEDORA", value:"2016-f4504e9445");

  script_name(english:"Fedora 23 : xen-4.5.2-9.fc23 (2016-f4504e9445)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Qemu: nvram: OOB r/w access in processing firmware configurations
CVE-2016-1714 (#1296080) Qemu: i386: NULL pointer dereference in
vapic_write() CVE-2016-1922 (#1292767) qemu: Stack-based buffer
overflow in megasas_ctrl_get_info CVE-2015-8613 (#1293305) qemu-kvm:
Infinite loop and out-of-bounds transfer start in start_xmit() and
e1000_receive_iov() CVE-2016-1981 (#1299996) Qemu: usb ehci
out-of-bounds read in ehci_process_itd (#1300235) Qemu: usb: ehci NULL
pointer dereference in ehci_caps_write CVE-2016-2198 (#1303135) Qemu:
net: ne2000: infinite loop in ne2000_receive CVE-2016-2841 (#1304048)
Qemu: usb: integer overflow in remote NDIS control message handling
CVE-2016-2538 (#1305816) Qemu: usb: NULL pointer dereference in remote
NDIS control message handling CVE-2016-2392 (#1307116) Qemu: usb:
multiple eof_timers in ohci module leads to NULL pointer dereference
CVE-2016-2391 (#1308882) Qemu: net: out of bounds read in
net_checksum_calculate() CVE-2016-2857 (#1309565) Qemu: OOB access in
address_space_rw leads to segmentation fault CVE-2015-8817
CVE-2015-8818 (#1313273) Qemu: rng-random: arbitrary stack based
allocation leading to corruption CVE-2016-2858 (#1314678)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1283934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1284008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1296060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1296567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1298570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1299455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1300771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1301643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1302299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1303106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1303120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1304794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1314676"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-March/179083.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?56044835"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"xen-4.5.2-9.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
