#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0428. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53352);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/01/04 16:02:21 $");

  script_cve_id("CVE-2011-0997");
  script_bugtraq_id(47176);
  script_osvdb_id(71493);
  script_xref(name:"RHSA", value:"2011:0428");

  script_name(english:"RHEL 4 / 5 / 6 : dhcp (RHSA-2011:0428)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dhcp packages that fix one security issue are now available
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
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0997.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0428.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdhcp4client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdhcp4client-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/11");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0428";
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
  if (rpm_check(release:"RHEL4", reference:"dhclient-3.0.1-67.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"dhcp-3.0.1-67.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"dhcp-devel-3.0.1-67.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"dhclient-3.0.5-23.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"dhclient-3.0.5-23.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"dhclient-3.0.5-23.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"dhcp-3.0.5-23.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"dhcp-3.0.5-23.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"dhcp-3.0.5-23.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"dhcp-devel-3.0.5-23.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libdhcp4client-3.0.5-23.el5_6.4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libdhcp4client-devel-3.0.5-23.el5_6.4")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dhclient-4.1.1-12.P1.el6_0.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dhclient-4.1.1-12.P1.el6_0.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dhclient-4.1.1-12.P1.el6_0.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dhcp-4.1.1-12.P1.el6_0.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dhcp-4.1.1-12.P1.el6_0.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dhcp-4.1.1-12.P1.el6_0.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"dhcp-debuginfo-4.1.1-12.P1.el6_0.4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"dhcp-devel-4.1.1-12.P1.el6_0.4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhclient / dhcp / dhcp-debuginfo / dhcp-devel / libdhcp4client / etc");
  }
}
