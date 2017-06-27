#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1814. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57295);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/04 16:12:17 $");

  script_cve_id("CVE-2011-4339");
  script_bugtraq_id(51036);
  script_osvdb_id(77748);
  script_xref(name:"RHSA", value:"2011:1814");

  script_name(english:"RHEL 6 : ipmitool (RHSA-2011:1814)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated ipmitool package that fixes one security issue is now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The ipmitool package contains a command line utility for interfacing
with devices that support the Intelligent Platform Management
Interface (IPMI) specification. IPMI is an open standard for machine
health, inventory, and remote power control.

It was discovered that the IPMI event daemon (ipmievd) created its
process ID (PID) file with world-writable permissions. A local user
could use this flaw to make the ipmievd init script kill an arbitrary
process when the ipmievd daemon is stopped or restarted.
(CVE-2011-4339)

All users of ipmitool are advised to upgrade to this updated package,
which contains a backported patch to correct this issue. After
installing this update, the IPMI event daemon (ipmievd) will be
restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4339.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1814.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ipmitool and / or ipmitool-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipmitool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipmitool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1814";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipmitool-1.8.11-12.el6_2.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipmitool-1.8.11-12.el6_2.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipmitool-1.8.11-12.el6_2.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ipmitool-debuginfo-1.8.11-12.el6_2.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ipmitool-debuginfo-1.8.11-12.el6_2.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ipmitool-debuginfo-1.8.11-12.el6_2.1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipmitool / ipmitool-debuginfo");
  }
}
