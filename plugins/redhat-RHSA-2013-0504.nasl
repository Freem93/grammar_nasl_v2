#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0504. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64755);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2012-3955");
  script_bugtraq_id(55530);
  script_osvdb_id(85424);
  script_xref(name:"RHSA", value:"2013:0504");

  script_name(english:"RHEL 6 : dhcp (RHSA-2013:0504)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dhcp packages that fix one security issue and two bugs are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The dhcp packages provide the Dynamic Host Configuration Protocol
(DHCP) that allows individual devices on an IP network to get their
own network configuration information, including an IP address, a
subnet mask, and a broadcast address.

A flaw was found in the way the dhcpd daemon handled the expiration
time of IPv6 leases. If dhcpd's configuration was changed to reduce
the default IPv6 lease time, lease renewal requests for previously
assigned leases could cause dhcpd to crash. (CVE-2012-3955)

This update also fixes the following bugs :

* Prior to this update, the DHCP server discovered only the first IP
address of a network interface if the network interface had more than
one configured IP address. As a consequence, the DHCP server failed to
restart if the server was configured to serve only a subnet of the
following IP addresses. This update modifies network interface
addresses discovery code to find all addresses of a network interface.
The DHCP server can also serve subnets of other addresses. (BZ#803540)

* Prior to this update, the dhclient rewrote the /etc/resolv.conf file
with backup data after it was stopped even when the PEERDNS flag was
set to 'no' before shut down if the configuration file was changed
while the dhclient ran with PEERDNS=yes. This update removes the
backing up and restoring functions for this configuration file from
the dhclient-script. Now, the dhclient no longer rewrites the
/etc/resolv.conf file when stopped. (BZ#824622)

All users of DHCP are advised to upgrade to these updated packages,
which fix these issues. After installing this update, all DHCP servers
will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3955.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0504.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:0504";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dhclient-4.1.1-34.P1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dhclient-4.1.1-34.P1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dhclient-4.1.1-34.P1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dhcp-4.1.1-34.P1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dhcp-4.1.1-34.P1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dhcp-4.1.1-34.P1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dhcp-common-4.1.1-34.P1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dhcp-common-4.1.1-34.P1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dhcp-common-4.1.1-34.P1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"dhcp-debuginfo-4.1.1-34.P1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"dhcp-devel-4.1.1-34.P1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhclient / dhcp / dhcp-common / dhcp-debuginfo / dhcp-devel");
  }
}
