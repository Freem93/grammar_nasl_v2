#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0581 and 
# Oracle Linux Security Advisory ELSA-2008-0581 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67723);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/26 16:04:31 $");

  script_cve_id("CVE-2008-2374");
  script_bugtraq_id(30105);
  script_xref(name:"RHSA", value:"2008:0581");

  script_name(english:"Oracle Linux 4 / 5 : bluez-libs / bluez-utils (ELSA-2008-0581)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0581 :

Updated bluez-libs and bluez-utils packages that fix a security flaw
are now available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The bluez-libs package contains libraries for use in Bluetooth
applications. The bluez-utils package contains Bluetooth daemons and
utilities.

An input validation flaw was found in the Bluetooth Session
Description Protocol (SDP) packet parser used by the Bluez Bluetooth
utilities. A Bluetooth device with an already-established trust
relationship, or a local user registering a service record via a
UNIX(r) socket or D-Bus interface, could cause a crash, or possibly
execute arbitrary code with privileges of the hcid daemon.
(CVE-2008-2374)

Users of bluez-libs and bluez-utils are advised to upgrade to these
updated packages, which contains a backported patch to correct this
issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-July/000677.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-July/000679.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bluez-libs and / or bluez-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bluez-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bluez-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bluez-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bluez-utils-cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/14");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"bluez-libs-2.10-3")) flag++;
if (rpm_check(release:"EL4", reference:"bluez-libs-devel-2.10-3")) flag++;
if (rpm_check(release:"EL4", reference:"bluez-utils-2.10-2.4")) flag++;
if (rpm_check(release:"EL4", reference:"bluez-utils-cups-2.10-2.4")) flag++;

if (rpm_check(release:"EL5", reference:"bluez-libs-3.7-1.1")) flag++;
if (rpm_check(release:"EL5", reference:"bluez-libs-devel-3.7-1.1")) flag++;
if (rpm_check(release:"EL5", reference:"bluez-utils-3.7-2.2")) flag++;
if (rpm_check(release:"EL5", reference:"bluez-utils-cups-3.7-2.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bluez-libs / bluez-libs-devel / bluez-utils / bluez-utils-cups");
}
