#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2013-0003.
#

include("compat.inc");

if (description)
{
  script_id(79495);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2012-2375", "CVE-2012-4565", "CVE-2012-5517");
  script_bugtraq_id(53615, 56346, 56527);
  script_osvdb_id(77100);

  script_name(english:"OracleVM 3.2 : kernel-uek (OVMSA-2013-0003)");
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

  - bonding: fixup typo in rlb mode of bond and bridge fix
    (Guru Anbalagane) [Orabug: 16069448]

  - bonding: rlb mode of bond should not alter ARP
    originating via bridge (zheng.li) [Orabug: 14650975]

  - compilation fix oracleasm typo (Maxim Uvarov)

  - mm/hotplug: correctly add new zone to all other nodes'
    zone lists (Jiang Liu) [Orabug: 16020976 Bug-db: 14798]
    (CVE-2012-5517)

  - Divide by zero in TCP congestion control Algorithm.
    (Jesper Dangaard Brouer) [Orabug: 16020656 Bug-db:
    14798] (CVE-2012-4565)

  - Fix length of buffer copied in __nfs4_get_acl_uncached
    (Sachin Prabhu) [Bug- db: 14798] (CVE-2012-2375)

  - Avoid reading past buffer when calling GETACL (Sachin
    Prabhu) [Bug-db: 14798] (CVE-2012-2375)

  - Avoid beyond bounds copy while caching ACL (Sachin
    Prabhu) [Bug-db: 14798] (CVE-2012-2375)

  - oracleasm: Introduce module parameter for block size
    selection (Martin K. Petersen) [Orabug: 15924773
    16017829]

  - kernel posttrans remove all crashkernel=* (Jason Luan)
    [Orabug: 15882974]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2013-January/000121.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a925726"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/18");
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
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-2.6.39-300.26.1.el5uek")) flag++;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-firmware-2.6.39-300.26.1.el5uek")) flag++;

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
