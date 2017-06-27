#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0581. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33497);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2008-2374");
  script_bugtraq_id(30105);
  script_xref(name:"RHSA", value:"2008:0581");

  script_name(english:"RHEL 4 / 5 : bluez-libs and bluez-utils (RHSA-2008:0581)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bluez-libs and bluez-utils packages that fix a security flaw
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
    value:"https://www.redhat.com/security/data/cve/CVE-2008-2374.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0581.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-utils-cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0581";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"bluez-libs-2.10-3")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"bluez-libs-2.10-3")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"bluez-libs-devel-2.10-3")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"bluez-libs-devel-2.10-3")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"bluez-utils-2.10-2.4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"bluez-utils-2.10-2.4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"bluez-utils-cups-2.10-2.4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"bluez-utils-cups-2.10-2.4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bluez-libs-3.7-1.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bluez-libs-3.7-1.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bluez-libs-devel-3.7-1.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bluez-libs-devel-3.7-1.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bluez-utils-3.7-2.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bluez-utils-3.7-2.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bluez-utils-cups-3.7-2.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bluez-utils-cups-3.7-2.2")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bluez-libs / bluez-libs-devel / bluez-utils / bluez-utils-cups");
  }
}
