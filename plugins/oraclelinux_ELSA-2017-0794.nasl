#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:0794 and 
# Oracle Linux Security Advisory ELSA-2017-0794 respectively.
#

include("compat.inc");

if (description)
{
  script_id(99073);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id("CVE-2013-2236", "CVE-2016-1245", "CVE-2016-2342", "CVE-2016-4049", "CVE-2017-5495");
  script_osvdb_id(94839, 135746, 137736, 146004, 150789);
  script_xref(name:"RHSA", value:"2017:0794");

  script_name(english:"Oracle Linux 6 : quagga (ELSA-2017-0794)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:0794 :

An update for quagga is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The quagga packages contain Quagga, the free network-routing software
suite that manages TCP/IP based protocols. Quagga supports the BGP4,
BGP4+, OSPFv2, OSPFv3, RIPv1, RIPv2, and RIPng protocols, and is
intended to be used as a Route Server and Route Reflector.

Security Fix(es) :

* A stack-based buffer overflow flaw was found in the way Quagga
handled IPv6 router advertisement messages. A remote attacker could
use this flaw to crash the zebra daemon resulting in denial of
service. (CVE-2016-1245)

* A stack-based buffer overflow flaw was found in the way the Quagga
BGP routing daemon (bgpd) handled Labeled-VPN SAFI routes data. A
remote attacker could use this flaw to crash the bgpd daemon resulting
in denial of service. (CVE-2016-2342)

* A denial of service flaw was found in the Quagga BGP routing daemon
(bgpd). Under certain circumstances, a remote attacker could send a
crafted packet to crash the bgpd daemon resulting in denial of
service. (CVE-2016-4049)

* A denial of service flaw affecting various daemons in Quagga was
found. A remote attacker could use this flaw to cause the various
Quagga daemons, which expose their telnet interface, to crash.
(CVE-2017-5495)

* A stack-based buffer overflow flaw was found in the way the Quagga
OSPFD daemon handled LSA (link-state advertisement) packets. A remote
attacker could use this flaw to crash the ospfd daemon resulting in
denial of service. (CVE-2013-2236)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.9 Release Notes and Red Hat Enterprise Linux 6.9
Technical Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-March/006802.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected quagga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:quagga-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"quagga-0.99.15-14.el6")) flag++;
if (rpm_check(release:"EL6", reference:"quagga-contrib-0.99.15-14.el6")) flag++;
if (rpm_check(release:"EL6", reference:"quagga-devel-0.99.15-14.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga / quagga-contrib / quagga-devel");
}
