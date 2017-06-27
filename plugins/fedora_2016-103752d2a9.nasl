#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-103752d2a9.
#

include("compat.inc");

if (description)
{
  script_id(92059);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/10/18 16:42:53 $");

  script_cve_id("CVE-2016-2858", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4962", "CVE-2016-4963", "CVE-2016-5238", "CVE-2016-5242", "CVE-2016-5337", "CVE-2016-5338");
  script_xref(name:"FEDORA", value:"2016-103752d2a9");

  script_name(english:"Fedora 23 : xen (2016-103752d2a9)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Qemu: scsi: esp: OOB r/w access while processing ESP_FIFO
[CVE-2016-5338] (#1343323) Qemu: scsi: megasas: information leakage in
megasas_ctrl_get_info [CVE-2016-5337] (#1343909)

----

fix for CVE-2016-2858 doesn't build with qemu-xen enabled Unsanitised
guest input in libxl device handling code [XSA-175, CVE-2016-4962]
(#1342132) Unsanitised driver domain input in libxl device handling
[XSA-178, CVE-2016-4963] (#1342131) arm: Host crash caused by VMID
exhaust [XSA-181] (#1342530) Qemu: display: vmsvga: out-of-bounds read
in vmsvga_fifo_read_raw() routine [CVE-2016-4454] (#1340741) Qemu:
display: vmsvga: infinite loop in vmsvga_fifo_run() routine
[CVE-2016-4453] (#1340746) Qemu: scsi: esp: OOB write when using
non-DMA mode in get_cmd [CVE-2016-5238] (#1341931)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-103752d2a9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/14");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC23", reference:"xen-4.5.3-8.fc23")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
