#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1552. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92718);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/02/13 20:45:10 $");

  script_cve_id("CVE-2015-7979", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1550", "CVE-2016-2518");
  script_osvdb_id(133391, 137711, 137712, 137714, 137734);
  script_xref(name:"RHSA", value:"2016:1552");

  script_name(english:"RHEL 6 : ntp (RHSA-2016:1552)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ntp is now available for Red Hat Enterprise Linux 6.7
Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Network Time Protocol (NTP) is used to synchronize a computer's
time with another referenced time source. These packages include the
ntpd service which continuously adjusts system time and utilities used
to query and configure the ntpd service.

Security Fix(es) :

* It was found that when NTP was configured in broadcast mode, a
remote attacker could broadcast packets with bad authentication to all
clients. The clients, upon receiving the malformed packets, would
break the association with the broadcast server, causing them to
become out of sync over a longer period of time. (CVE-2015-7979)

* A denial of service flaw was found in the way NTP handled
preemptable client associations. A remote attacker could send several
crypto NAK packets to a victim client, each with a spoofed source
address of an existing associated peer, preventing that client from
synchronizing its time. (CVE-2016-1547)

* It was found that an ntpd client could be forced to change from
basic client/server mode to the interleaved symmetric mode. A remote
attacker could use a spoofed packet that, when processed by an ntpd
client, would cause that client to reject all future legitimate server
responses, effectively disabling time synchronization on that client.
(CVE-2016-1548)

* A flaw was found in the way NTP's libntp performed message
authentication. An attacker able to observe the timing of the
comparison function used in packet authentication could potentially
use this flaw to recover the message digest. (CVE-2016-1550)

* An out-of-bounds access flaw was found in the way ntpd processed
certain packets. An authenticated attacker could use a crafted packet
to create a peer association with hmode of 7 and larger, which could
potentially (although highly unlikely) cause ntpd to crash.
(CVE-2016-2518)

The CVE-2016-1548 issue was discovered by Miroslav Lichvar (Red Hat)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7979.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-1547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-1548.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-1550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-2518.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-1552.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6\.7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.7", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1552";
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
  if (rpm_check(release:"RHEL6", sp:"7", cpu:"i686", reference:"ntp-4.2.6p5-5.el6_7.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", cpu:"s390x", reference:"ntp-4.2.6p5-5.el6_7.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", cpu:"x86_64", reference:"ntp-4.2.6p5-5.el6_7.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", cpu:"i686", reference:"ntp-debuginfo-4.2.6p5-5.el6_7.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", cpu:"s390x", reference:"ntp-debuginfo-4.2.6p5-5.el6_7.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", cpu:"x86_64", reference:"ntp-debuginfo-4.2.6p5-5.el6_7.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", reference:"ntp-doc-4.2.6p5-5.el6_7.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", cpu:"i686", reference:"ntp-perl-4.2.6p5-5.el6_7.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", cpu:"s390x", reference:"ntp-perl-4.2.6p5-5.el6_7.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", cpu:"x86_64", reference:"ntp-perl-4.2.6p5-5.el6_7.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", cpu:"i686", reference:"ntpdate-4.2.6p5-5.el6_7.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", cpu:"s390x", reference:"ntpdate-4.2.6p5-5.el6_7.5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"7", cpu:"x86_64", reference:"ntpdate-4.2.6p5-5.el6_7.5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-doc / ntp-perl / ntpdate");
  }
}
