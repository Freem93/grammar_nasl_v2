#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0252. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97011);
  script_version("$Revision: 3.6 $");
  script_cvs_date("$Date: 2017/04/17 17:37:51 $");

  script_cve_id("CVE-2016-7426", "CVE-2016-7429", "CVE-2016-7433", "CVE-2016-9310", "CVE-2016-9311");
  script_osvdb_id(147594, 147595, 147601, 147602, 147603);
  script_xref(name:"RHSA", value:"2017:0252");

  script_name(english:"RHEL 6 / 7 : ntp (RHSA-2017:0252)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ntp is now available for Red Hat Enterprise Linux 6 and
Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Network Time Protocol (NTP) is used to synchronize a computer's
time with another referenced time source. These packages include the
ntpd service which continuously adjusts system time and utilities used
to query and configure the ntpd service.

Security Fix(es) :

* It was found that when ntp is configured with rate limiting for all
associations the limits are also applied to responses received from
its configured sources. A remote attacker who knows the sources can
cause a denial of service by preventing ntpd from accepting valid
responses from its sources. (CVE-2016-7426)

* A flaw was found in the control mode functionality of ntpd. A remote
attacker could send a crafted control mode packet which could lead to
information disclosure or result in DDoS amplification attacks.
(CVE-2016-9310)

* A flaw was found in the way ntpd implemented the trap service. A
remote attacker could send a specially crafted packet to cause a NULL
pointer dereference that will crash ntpd, resulting in a denial of
service. (CVE-2016-9311)

* A flaw was found in the way ntpd running on a host with multiple
network interfaces handled certain server responses. A remote attacker
could use this flaw which would cause ntpd to not synchronize with the
source. (CVE-2016-7429)

* A flaw was found in the way ntpd calculated the root delay. A remote
attacker could send a specially crafted spoofed packet to cause denial
of service or in some special cases even crash. (CVE-2016-7433)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-7426.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-7429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-7433.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-9310.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-9311.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0252.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:0252";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ntp-4.2.6p5-10.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ntp-4.2.6p5-10.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ntp-4.2.6p5-10.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ntp-debuginfo-4.2.6p5-10.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ntp-debuginfo-4.2.6p5-10.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ntp-debuginfo-4.2.6p5-10.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ntp-doc-4.2.6p5-10.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ntp-perl-4.2.6p5-10.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ntp-perl-4.2.6p5-10.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ntp-perl-4.2.6p5-10.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ntpdate-4.2.6p5-10.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ntpdate-4.2.6p5-10.el6_8.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ntpdate-4.2.6p5-10.el6_8.2")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ntp-4.2.6p5-25.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ntp-4.2.6p5-25.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ntp-debuginfo-4.2.6p5-25.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ntp-debuginfo-4.2.6p5-25.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ntp-doc-4.2.6p5-25.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ntp-perl-4.2.6p5-25.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ntpdate-4.2.6p5-25.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ntpdate-4.2.6p5-25.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"sntp-4.2.6p5-25.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"sntp-4.2.6p5-25.el7_3.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-doc / ntp-perl / ntpdate / sntp");
  }
}
