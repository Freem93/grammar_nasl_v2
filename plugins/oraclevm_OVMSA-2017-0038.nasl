#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0038.
#

include("compat.inc");

if (description)
{
  script_id(97058);
  script_version("$Revision: 3.6 $");
  script_cvs_date("$Date: 2017/04/17 17:37:51 $");

  script_cve_id("CVE-2013-5211", "CVE-2016-7426", "CVE-2016-7429", "CVE-2016-7433", "CVE-2016-9310", "CVE-2016-9311");
  script_bugtraq_id(64692);
  script_osvdb_id(101576, 147594, 147595, 147601, 147602, 147603);

  script_name(english:"OracleVM 3.3 / 3.4 : ntp (OVMSA-2017-0038)");
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

  - add disable monitor to default ntp.conf [CVE-2013-5211]

  - don't limit rate of packets from sources (CVE-2016-7426)

  - don't change interface from received packets
    (CVE-2016-7429)

  - fix calculation of root distance again (CVE-2016-7433)

  - require authentication for trap commands (CVE-2016-9310)

  - fix crash when reporting peer event to trappers
    (CVE-2016-9311)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-February/000645.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?798cb9e7"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-February/000646.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c07bfe5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ntp / ntpdate packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"ntp-4.2.6p5-10.0.1.el6_8.2")) flag++;
if (rpm_check(release:"OVS3.3", reference:"ntpdate-4.2.6p5-10.0.1.el6_8.2")) flag++;

if (rpm_check(release:"OVS3.4", reference:"ntp-4.2.6p5-10.0.1.el6_8.2")) flag++;
if (rpm_check(release:"OVS3.4", reference:"ntpdate-4.2.6p5-10.0.1.el6_8.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntpdate");
}
