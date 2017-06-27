#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0056.
#

include("compat.inc");

if (description)
{
  script_id(83108);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2014-3215", "CVE-2014-8171", "CVE-2014-9529", "CVE-2014-9584");
  script_bugtraq_id(67341, 71880, 71883, 74293);
  script_osvdb_id(116762, 116767, 121104);

  script_name(english:"OracleVM 3.3 : kernel-uek (OVMSA-2015-0056)");
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

  - isofs: Fix unchecked printing of ER records (Jan Kara)
    [Orabug: 20930551] (CVE-2014-9584)

  - KEYS: close race between key lookup and freeing (Sasha
    Levin) [Orabug: 20930548] (CVE-2014-9529)
    (CVE-2014-9529)

  - mm: memcg: do not allow task about to OOM kill to bypass
    the limit (Johannes Weiner) [Orabug: 20930539]
    (CVE-2014-8171)

  - mm: memcg: do not declare OOM from __GFP_NOFAIL
    allocations (Johannes Weiner) [Orabug: 20930539]
    (CVE-2014-8171)

  - fs: buffer: move allocation failure loop into the
    allocator (Johannes Weiner) [Orabug: 20930539]
    (CVE-2014-8171)

  - mm: memcg: handle non-error OOM situations more
    gracefully (Johannes Weiner) [Orabug: 20930539]
    (CVE-2014-8171)

  - mm: memcg: do not trap chargers with full callstack on
    OOM (Johannes Weiner) [Orabug: 20930539] (CVE-2014-8171)

  - mm: memcg: rework and document OOM waiting and wakeup
    (Johannes Weiner) [Orabug: 20930539] (CVE-2014-8171)

  - mm: memcg: enable memcg OOM killer only for user faults
    (Johannes Weiner) [Orabug: 20930539] (CVE-2014-8171)

  - x86: finish user fault error path with fatal signal
    (Johannes Weiner) [Orabug: 20930539] (CVE-2014-8171)

  - arch: mm: pass userspace fault flag to generic fault
    handler (Johannes Weiner) [Orabug: 20930539]
    (CVE-2014-8171)

  - selinux: Permit bounded transitions under NO_NEW_PRIVS
    or NOSUID. (Stephen Smalley) [Orabug: 20930501]
    (CVE-2014-3215)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2015-April/000307.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1c84d76"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-3.8.13-68.1.3.el6uek")) flag++;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-firmware-3.8.13-68.1.3.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
