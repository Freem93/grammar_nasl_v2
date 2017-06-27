#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-11021.
#

include("compat.inc");

if (description)
{
  script_id(47839);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 21:05:30 $");

  script_cve_id("CVE-2010-2237", "CVE-2010-2238", "CVE-2010-2239", "CVE-2010-2242");
  script_xref(name:"FEDORA", value:"2010-11021");

  script_name(english:"Fedora 12 : libvirt-0.8.2-1.fc12 (2010-11021)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A reboot is required to update the iptables rules for the default
virtual network to address the CVE-2010-2242 All disk format probing
is now disabled in a default installation of libvirt. This change may
prevent KVM guests using qcow2 disks from booting successfully. If
this occurs verify that the guest XML <disk> element has explicitly
requested use of the qcow2 data format via the <driver> element:
<driver name='qemu' type='qcow2'/> If the qcow2 is using an external
backing file, it may be necessary to re-create the qcow2 file,
explicitly specifying the backing store format with the '-o' option.
qemu- img create -f qcow2 -b master.qcow2 -o backing_fmt=qcow2
newdisk.qcow2 If this is not possible, disk format probing can be
re-enabled via /etc/libvirt/qemu.conf allow_disk_format_probing = 1
NB, enabling disk format probing has security consequences as per the
linked CVEs.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=602455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=607810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=607811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=607812"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044579.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ecda916b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"libvirt-0.8.2-1.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
