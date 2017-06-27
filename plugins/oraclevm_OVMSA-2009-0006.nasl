#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2009-0006.
#

include("compat.inc");

if (description)
{
  script_id(79454);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2009-1185");
  script_bugtraq_id(34536);
  script_osvdb_id(53810);

  script_name(english:"OracleVM 2.1 : udev (OVMSA-2009-0006)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

CVE-2009-1185 udev before 1.4.1 does not verify whether a NETLINK
message originates from kernel space, which allows local users to gain
privileges by sending a NETLINK message from user space.

  - fix for CVE-2009-1185 (bug #495051)

  - Resolves: rhbz#495055

  - removed zaptel rules (rhbz #294061)

  - fixed segfault for empty lines in passwd (rhbz#413831)

  - added patch for iscsi ids (Daniel Berrange)
    (rhbz#427640)

  - added /etc/sysconfig/udev-stw, which makes MODULES
    configurable (Jeff Bastian) (rhbz#437979)

  - added ext4 support to vol_id (rhbz#444528)

  - updated dasd_id from dasdinfo of s390-tools-1.6.2
    (rhbz#430532)

  - Resolves: rhbz#294061, rhbz#413831, rhbz#427640

  - Resolves: rhbz#437979, rhbz#444528, rhbz#430532

  - scsi_id, retry open on EBUSY (rhbz#450279)

  - Resolves: rhbz#450279

  - set selinux context for .udev dirs and symlinks
    (rhbz#442886)

  - fixed rule for hp iLO2 virtual mouse device
    (rhbz#429215)

  - Resolves: rhbz#429215, rhbz#442886

  - fixed selinux context setting for symlinks (rhbz#441054)

  - Resolves: rhbz#441054

  - fixed regression bug rhbz#430667 introduced by fix for
    rhbz#275441

  - Resolves: rhbz#275441

  - added rule for hp iLO2 virtual mouse device
    (rhbz#429215)

  - Resolves: rhbz#429215

  - fix for looping vol_id, because of a malformed passwd
    (rhbz#425941)

  - revised fix for tape devices (rhbz#231990)

  - Resolves: rhbz#425941, rhbz#231990

  - moved 'ignore_device' for dm devices to 90-dm.rules
    (rhbz#275441)

  - added cciss support (rhbz#250484)

  - support more than 10 nst devices in the persistent rules
    (rhbz#231990)

  - extra double check for symlinks improved (rhbz#217917)

  - Resolves: rhbz#217917, rhbz#231990, rhbz#250484,
    rhbz#275441

  - do not fail, if EEXIST on symlink (#217917)

  - Resolves: rhbz#217917

  - corrected rules for tape devices (#231990)

  - Resolves: rhbz#231990

  - removed pie link flag from static build flags

  - Resolves: rhbz#233956, rhbz#233307, rhbz#226997,
    rhbz#236242

  - Resolves: rhbz#217917, rhbz#231990

  - added RPM_OPT_FLAGS and pie to static build flags

  - Resolves: rhbz#233956, rhbz#233307, rhbz#226997,
    rhbz#236242

  - Resolves: rhbz#217917, rhbz#231990

  - do not fail, if EEXIST on mkdir (#217917)

  - configure process numbers dynamically according to CPU
    and MEM (#226997)

  - link statically (#236242, #233307)

  - fixed rule for raw1394 (#233956)

  - added persistent device names for tape devices (#231990)

  - Resolves: rhbz#233956, rhbz#233307, rhbz#226997,
    rhbz#236242

  - Resolves: rhbz#217917, rhbz#231990"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2009-April/000020.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f660381b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvolume_id / udev packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux udev Netlink Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libvolume_id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:udev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "2\.1" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.1", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.1", reference:"libvolume_id-095-14.20.el5_3")) flag++;
if (rpm_check(release:"OVS2.1", reference:"udev-095-14.20.el5_3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvolume_id / udev");
}
