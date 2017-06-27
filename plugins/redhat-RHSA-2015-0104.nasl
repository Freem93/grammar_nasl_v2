#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0104. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81071);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/06 15:51:00 $");

  script_cve_id("CVE-2014-9293", "CVE-2014-9294", "CVE-2014-9295", "CVE-2014-9296");
  script_osvdb_id(116066, 116067, 116068, 116069, 116070, 116074);
  script_xref(name:"RHSA", value:"2015:0104");

  script_name(english:"RHEL 6 : ntp (RHSA-2015:0104)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ntp packages that fix several security issues are now
available for Red Hat Enterprise Linux 6.5 Extended Update Support.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The Network Time Protocol (NTP) is used to synchronize a computer's
time with a referenced time source.

Multiple buffer overflow flaws were discovered in ntpd's
crypto_recv(), ctl_putdata(), and configure() functions. A remote
attacker could use either of these flaws to send a specially crafted
request packet that could crash ntpd or, potentially, execute
arbitrary code with the privileges of the ntp user. Note: the
crypto_recv() flaw requires non-default configurations to be active,
while the ctl_putdata() flaw, by default, can only be exploited via
local attackers, and the configure() flaw requires additional
authentication to exploit. (CVE-2014-9295)

It was found that ntpd automatically generated weak keys for its
internal use if no ntpdc request authentication key was specified in
the ntp.conf configuration file. A remote attacker able to match the
configured IP restrictions could guess the generated key, and possibly
use it to send ntpdc query or configuration requests. (CVE-2014-9293)

It was found that ntp-keygen used a weak method for generating MD5
keys. This could possibly allow an attacker to guess generated MD5
keys that could then be used to spoof an NTP client or server. Note:
it is recommended to regenerate any MD5 keys that had explicitly been
generated with ntp-keygen; the default installation does not contain
such keys. (CVE-2014-9294)

A missing return statement in the receive() function could potentially
allow a remote attacker to bypass NTP's authentication mechanism.
(CVE-2014-9296)

All ntp users are advised to upgrade to this updated package, which
contains backported patches to resolve these issues. After installing
the update, the ntpd daemon will restart automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9293.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9294.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9295.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9296.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0104.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6\.5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.5", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0104";
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
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"ntp-4.2.6p5-2.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"ntp-4.2.6p5-2.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"ntp-4.2.6p5-2.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"ntp-debuginfo-4.2.6p5-2.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"ntp-debuginfo-4.2.6p5-2.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"ntp-debuginfo-4.2.6p5-2.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"ntp-doc-4.2.6p5-2.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"ntp-perl-4.2.6p5-2.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"ntp-perl-4.2.6p5-2.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"ntp-perl-4.2.6p5-2.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"ntpdate-4.2.6p5-2.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"ntpdate-4.2.6p5-2.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"ntpdate-4.2.6p5-2.el6_5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp / ntp-debuginfo / ntp-doc / ntp-perl / ntpdate");
  }
}
