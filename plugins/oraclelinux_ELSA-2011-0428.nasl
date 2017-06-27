#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0428 and 
# Oracle Linux Security Advisory ELSA-2011-0428 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68251);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/17 13:39:45 $");

  script_cve_id("CVE-2011-0997");
  script_bugtraq_id(47176);
  script_osvdb_id(71493);
  script_xref(name:"RHSA", value:"2011:0428");

  script_name(english:"Oracle Linux 4 / 5 / 6 : dhcp (ELSA-2011-0428)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0428 :

Updated dhcp packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The Dynamic Host Configuration Protocol (DHCP) is a protocol that
allows individual devices on an IP network to get their own network
configuration information, including an IP address, a subnet mask, and
a broadcast address.

It was discovered that the DHCP client daemon, dhclient, did not
sufficiently sanitize certain options provided in DHCP server replies,
such as the client hostname. A malicious DHCP server could send such
an option with a specially crafted value to a DHCP client. If this
option's value was saved on the client system, and then later
insecurely evaluated by a process that assumes the option is trusted,
it could lead to arbitrary code execution with the privileges of that
process. (CVE-2011-0997)

Red Hat would like to thank Sebastian Krahmer of the SuSE Security
Team for reporting this issue.

All dhclient users should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-April/002062.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-April/002063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-April/002064.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libdhcp4client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libdhcp4client-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"dhclient-3.0.1-67.el4")) flag++;
if (rpm_check(release:"EL4", reference:"dhcp-3.0.1-67.el4")) flag++;
if (rpm_check(release:"EL4", reference:"dhcp-devel-3.0.1-67.el4")) flag++;

if (rpm_check(release:"EL5", reference:"dhclient-3.0.5-23.el5_6.4")) flag++;
if (rpm_check(release:"EL5", reference:"dhcp-3.0.5-23.el5_6.4")) flag++;
if (rpm_check(release:"EL5", reference:"dhcp-devel-3.0.5-23.el5_6.4")) flag++;
if (rpm_check(release:"EL5", reference:"libdhcp4client-3.0.5-23.el5_6.4")) flag++;
if (rpm_check(release:"EL5", reference:"libdhcp4client-devel-3.0.5-23.el5_6.4")) flag++;

if (rpm_check(release:"EL6", reference:"dhclient-4.1.1-12.P1.el6_0.4")) flag++;
if (rpm_check(release:"EL6", reference:"dhcp-4.1.1-12.P1.el6_0.4")) flag++;
if (rpm_check(release:"EL6", reference:"dhcp-devel-4.1.1-12.P1.el6_0.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhclient / dhcp / dhcp-devel / libdhcp4client / etc");
}
