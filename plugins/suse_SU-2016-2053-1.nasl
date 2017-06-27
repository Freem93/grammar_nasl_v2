#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2053-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93287);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2016-5008");
  script_osvdb_id(140745);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libvirt (SUSE-SU-2016:2053-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libvirt fixes one security issue :

  - CVE-2016-5008: Empty VNC password disables
    authentication. (bsc#987527) Additionally, the update
    includes the following non-security fixes :

  - Improve waiting for block job readines in virsh.
    (bsc#989755)

  - Parse negative values in augeas lenses. (bsc#975729)

  - Restart daemons in %posttrans after connection drivers
    have been processed. (bsc#854343, bsc#968483)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/854343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5008.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162053-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?881eb91c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1:zypper in -t patch
SUSE-SLE-WE-12-SP1-2016-1208=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1208=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1208=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1208=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-interface-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-libxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-libxl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-lxc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-network-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-nodedev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-nwfilter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-secret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-lock-sanlock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-xen-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-client-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-client-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-config-network-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-config-nwfilter-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-interface-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-interface-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-lxc-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-lxc-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-network-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-network-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-nodedev-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-nodedev-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-nwfilter-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-nwfilter-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-qemu-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-qemu-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-secret-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-secret-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-storage-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-driver-storage-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-lxc-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-daemon-qemu-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-debugsource-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-doc-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-lock-sanlock-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libvirt-lock-sanlock-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-client-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-client-32bit-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-client-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-client-debuginfo-32bit-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-config-network-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-network-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-network-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-debuginfo-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-lxc-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-qemu-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-daemon-xen-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-debugsource-1.2.18.4-11.7")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvirt-doc-1.2.18.4-11.7")) flag++;


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
