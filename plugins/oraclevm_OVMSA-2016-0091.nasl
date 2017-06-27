#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0091.
#

include("compat.inc");

if (description)
{
  script_id(92658);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/14 17:23:20 $");

  script_cve_id("CVE-2016-2117", "CVE-2016-6197", "CVE-2016-6198");
  script_osvdb_id(135961, 141571);

  script_name(english:"OracleVM 3.4 : kernel-uek (OVMSA-2016-0091)");
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

  - vfs: rename: check backing inode being equal (Miklos
    Szeredi) [Orabug: 24010060] (CVE-2016-6198)
    (CVE-2016-6197)

  - vfs: add vfs_select_inode helper (Miklos Szeredi)
    [Orabug: 24010060] (CVE-2016-6198) (CVE-2016-6197)

  - ovl: verify upper dentry before unlink and rename
    (Miklos Szeredi) [Orabug: 24010060] (CVE-2016-6198)
    (CVE-2016-6197)

  - ovl: fix getcwd failure after unsuccessful rmdir (Rui
    Wang) [Orabug: 24010060] (CVE-2016-6198) (CVE-2016-6197)

  - xen: use same main loop for counting and remapping pages
    (Juergen Gross) [Orabug: 24012238]

  - Revert 'ocfs2: bump up o2cb network protocol version'
    (Junxiao Bi) 

  - atl2: Disable unimplemented scatter/gather feature (Ben
    Hutchings) [Orabug: 23704078] (CVE-2016-2117)

  - Revert 'perf tools: Bump default sample freq to 4 kHz'
    (ashok.vairavan) [Orabug: 23634802]

  - block: Initialize max_dev_sectors to 0 (Keith Busch)
    [Orabug: 23333444]

  - sd: Fix rw_max for devices that report an optimal xfer
    size (Martin K. Petersen) [Orabug: 23333444]

  - sd: Fix excessive capacity printing on devices with
    blocks bigger than 512 bytes (Martin K. Petersen)
    [Orabug: 23333444]

  - sd: Optimal I/O size is in bytes, not sectors (Martin K.
    Petersen) 

  - sd: Reject optimal transfer length smaller than page
    size (Martin K. Petersen) [Orabug: 23333444]

  - Fix kabi issue for upstream commit ca369d51 (Joe Jin)
    [Orabug: 23333444]

  - block/sd: Fix device-imposed transfer length limits (Joe
    Jin)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-July/000506.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-37.6.1.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-37.6.1.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
