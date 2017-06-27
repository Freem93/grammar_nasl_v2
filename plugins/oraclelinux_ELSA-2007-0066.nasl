#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0066 and 
# Oracle Linux Security Advisory ELSA-2007-0066 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67449);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:16:26 $");

  script_cve_id("CVE-2007-0456", "CVE-2007-0457", "CVE-2007-0458", "CVE-2007-0459");
  script_osvdb_id(33073, 33074, 33075, 33076);
  script_xref(name:"RHSA", value:"2007:0066");

  script_name(english:"Oracle Linux 3 / 4 / 5 : wireshark (ELSA-2007-0066)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0066 :

New Wireshark packages that fix various security vulnerabilities are
now available. Wireshark was previously known as Ethereal.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Wireshark is a program for monitoring network traffic.

Several denial of service bugs were found in Wireshark's LLT, IEEE
802.11, http, and tcp protocol dissectors. It was possible for
Wireshark to crash or stop responding if it read a malformed packet
off the network. (CVE-2007-0456, CVE-2007-0457, CVE-2007-0458,
CVE-2007-0459)

Users of Wireshark should upgrade to these updated packages containing
Wireshark version 0.99.5, which is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000238.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-March/000068.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-March/000070.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"wireshark-0.99.5-EL3.1.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"wireshark-0.99.5-EL3.1.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"wireshark-gnome-0.99.5-EL3.1.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"wireshark-gnome-0.99.5-EL3.1.0.1")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"wireshark-0.99.5-EL4.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"wireshark-0.99.5-EL4.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"wireshark-gnome-0.99.5-EL4.1.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"wireshark-gnome-0.99.5-EL4.1.0.1")) flag++;

if (rpm_check(release:"EL5", reference:"wireshark-0.99.5-1.el5.0.1")) flag++;
if (rpm_check(release:"EL5", reference:"wireshark-gnome-0.99.5-1.el5.0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-gnome");
}
