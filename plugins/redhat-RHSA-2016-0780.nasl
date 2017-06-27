#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0780. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91076);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id("CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5219", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7852", "CVE-2015-7977", "CVE-2015-7978");
  script_osvdb_id(116071, 126663, 126664, 126665, 126666, 129302, 129307, 129311, 133378, 133384);
  script_xref(name:"RHSA", value:"2016:0780");
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"RHEL 6 : ntp (RHSA-2016:0780)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ntp is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Network Time Protocol (NTP) is used to synchronize a computer's
time with another referenced time source. These packages include the
ntpd service which continuously adjusts system time and utilities used
to query and configure the ntpd service.

Security Fix(es) :

* It was found that the fix for CVE-2014-9750 was incomplete: three
issues were found in the value length checks in NTP's ntp_crypto.c,
where a packet with particular autokey operations that contained
malicious data was not always being completely validated. A remote
attacker could use a specially crafted NTP packet to crash ntpd.
(CVE-2015-7691, CVE-2015-7692, CVE-2015-7702)

* A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If ntpd was
configured to use autokey authentication, an attacker could send
packets to ntpd that would, after several days of ongoing attack,
cause it to run out of memory. (CVE-2015-7701)

* An off-by-one flaw, leading to a buffer overflow, was found in
cookedprint functionality of ntpq. A specially crafted NTP packet
could potentially cause ntpq to crash. (CVE-2015-7852)

* A NULL pointer dereference flaw was found in the way ntpd processed
'ntpdc reslist' commands that queried restriction lists with a large
amount of entries. A remote attacker could potentially use this flaw
to crash ntpd. (CVE-2015-7977)

* A stack-based buffer overflow flaw was found in the way ntpd
processed 'ntpdc reslist' commands that queried restriction lists with
a large amount of entries. A remote attacker could use this flaw to
crash ntpd. (CVE-2015-7978)

* It was found that ntpd could crash due to an uninitialized variable
when processing malformed logconfig configuration commands.
(CVE-2015-5194)

* It was found that ntpd would exit with a segmentation fault when a
statistics type that was not enabled during compilation (e.g.
timingstats) was referenced by the statistics or filegen configuration
command. (CVE-2015-5195)

* It was discovered that the sntp utility could become unresponsive
due to being caught in an infinite loop when processing a crafted NTP
packet. (CVE-2015-5219)

* It was found that NTP's :config command could be used to set the
pidfile and driftfile paths without any restrictions. A remote
attacker could use this flaw to overwrite a file on the file system
with a file containing the pid of the ntpd process (immediately) or
the current estimated drift of the system clock (in hourly intervals).
(CVE-2015-7703)

The CVE-2015-5219 and CVE-2015-7703 issues were discovered by Miroslav
Lichvar (Red Hat).

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.8 Release Notes and Red Hat Enterprise Linux 6.8
Technical Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5194.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5195.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5219.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7691.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7692.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7701.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7702.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7703.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7852.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7977.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7978.html"
  );
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfcf474c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0780.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0780";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ntp-4.2.6p5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ntp-4.2.6p5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ntp-4.2.6p5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ntp-debuginfo-4.2.6p5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ntp-debuginfo-4.2.6p5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ntp-debuginfo-4.2.6p5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"ntp-doc-4.2.6p5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ntp-perl-4.2.6p5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ntp-perl-4.2.6p5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ntp-perl-4.2.6p5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ntpdate-4.2.6p5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ntpdate-4.2.6p5-10.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ntpdate-4.2.6p5-10.el6")) flag++;

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
