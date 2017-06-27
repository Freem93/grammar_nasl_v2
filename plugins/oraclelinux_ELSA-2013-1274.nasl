#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1274 and 
# Oracle Linux Security Advisory ELSA-2013-1274 respectively.
#

include("compat.inc");

if (description)
{
  script_id(70009);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 17:16:05 $");

  script_cve_id("CVE-2013-4325");
  script_bugtraq_id(62499);
  script_osvdb_id(97509);
  script_xref(name:"RHSA", value:"2013:1274");

  script_name(english:"Oracle Linux 6 : hplip (ELSA-2013-1274)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:1274 :

Updated hplip packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The hplip packages contain the Hewlett-Packard Linux Imaging and
Printing Project (HPLIP), which provides drivers for Hewlett-Packard
printers and multi-function peripherals.

HPLIP communicated with PolicyKit for authorization via a D-Bus API
that is vulnerable to a race condition. This could lead to intended
PolicyKit authorizations being bypassed. This update modifies HPLIP to
communicate with PolicyKit via a different API that is not vulnerable
to the race condition. (CVE-2013-4325)

All users of hplip are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-September/003679.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hplip packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hplip-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsane-hpaio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"hpijs-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"hplip-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"hplip-common-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"hplip-gui-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"hplip-libs-3.12.4-4.el6_4.1")) flag++;
if (rpm_check(release:"EL6", reference:"libsane-hpaio-3.12.4-4.el6_4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hpijs / hplip / hplip-common / hplip-gui / hplip-libs / etc");
}
