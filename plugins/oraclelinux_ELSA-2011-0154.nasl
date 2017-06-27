#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0154 and 
# Oracle Linux Security Advisory ELSA-2011-0154 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68181);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:57:58 $");

  script_cve_id("CVE-2010-4267");
  script_osvdb_id(70498);
  script_xref(name:"RHSA", value:"2011:0154");

  script_name(english:"Oracle Linux 5 / 6 : hplip (ELSA-2011-0154)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0154 :

Updated hplip packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Hewlett-Packard Linux Imaging and Printing (HPLIP) provides drivers
for Hewlett-Packard printers and multifunction peripherals, and tools
for installing, using, and configuring them.

A flaw was found in the way certain HPLIP tools discovered devices
using the SNMP protocol. If a user ran certain HPLIP tools that search
for supported devices using SNMP, and a malicious user is able to send
specially crafted SNMP responses, it could cause those HPLIP tools to
crash or, possibly, execute arbitrary code with the privileges of the
user running them. (CVE-2010-4267)

Red Hat would like to thank Sebastian Krahmer of the SuSE Security
Team for reporting this issue.

Users of hplip should upgrade to these updated packages, which contain
a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001887.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-January/001798.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hplip packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hpijs3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip3-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsane-hpaio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsane-hpaio3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"hpijs-1.6.7-6.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"hpijs3-3.9.8-11.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"hplip-1.6.7-6.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"hplip3-3.9.8-11.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"hplip3-common-3.9.8-11.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"hplip3-gui-3.9.8-11.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"hplip3-libs-3.9.8-11.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"libsane-hpaio-1.6.7-6.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"libsane-hpaio3-3.9.8-11.el5_6.1")) flag++;

if (rpm_check(release:"EL6", reference:"hpijs-3.9.8-33.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"hplip-3.9.8-33.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"hplip-common-3.9.8-33.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"hplip-gui-3.9.8-33.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"hplip-libs-3.9.8-33.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"libsane-hpaio-3.9.8-33.el6_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hpijs / hpijs3 / hplip / hplip-common / hplip-gui / hplip-libs / etc");
}
