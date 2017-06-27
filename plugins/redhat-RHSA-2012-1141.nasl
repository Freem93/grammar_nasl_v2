#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1141. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61405);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2012-3571", "CVE-2012-3954");
  script_bugtraq_id(54665);
  script_osvdb_id(84253, 84255);
  script_xref(name:"RHSA", value:"2012:1141");

  script_name(english:"RHEL 6 : dhcp (RHSA-2012:1141)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dhcp packages that fix three security issues are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Dynamic Host Configuration Protocol (DHCP) is a protocol that
allows individual devices on an IP network to get their own network
configuration information, including an IP address, a subnet mask, and
a broadcast address.

A denial of service flaw was found in the way the dhcpd daemon handled
zero-length client identifiers. A remote attacker could use this flaw
to send a specially crafted request to dhcpd, possibly causing it to
enter an infinite loop and consume an excessive amount of CPU time.
(CVE-2012-3571)

Two memory leak flaws were found in the dhcpd daemon. A remote
attacker could use these flaws to cause dhcpd to exhaust all available
memory by sending a large number of DHCP requests. (CVE-2012-3954)

Upstream acknowledges Markus Hietava of the Codenomicon CROSS project
as the original reporter of CVE-2012-3571, and Glen Eustace of Massey
University, New Zealand, as the original reporter of CVE-2012-3954.

Users of DHCP should upgrade to these updated packages, which contain
backported patches to correct these issues. After installing this
update, all DHCP servers will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3954.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isc.org/software/dhcp/advisories/cve-2012-3571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isc.org/software/dhcp/advisories/cve-2012-3954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1141.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:1141";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dhclient-4.1.1-31.P1.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dhclient-4.1.1-31.P1.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dhclient-4.1.1-31.P1.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dhcp-4.1.1-31.P1.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dhcp-4.1.1-31.P1.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dhcp-4.1.1-31.P1.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dhcp-common-4.1.1-31.P1.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dhcp-common-4.1.1-31.P1.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dhcp-common-4.1.1-31.P1.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"dhcp-debuginfo-4.1.1-31.P1.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"dhcp-devel-4.1.1-31.P1.el6_3.1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
