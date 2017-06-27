#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0190. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96791);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2017/03/15 21:22:53 $");

  script_cve_id("CVE-2017-5373", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5378", "CVE-2017-5380", "CVE-2017-5383", "CVE-2017-5386", "CVE-2017-5390", "CVE-2017-5396");
  script_osvdb_id(150831, 150832, 150834, 150836, 150837, 150858, 150859, 150860, 150861, 150862, 150863, 150864, 150865, 150866, 150875, 150878, 150881);
  script_xref(name:"RHSA", value:"2017:0190");

  script_name(english:"RHEL 5 / 6 / 7 : firefox (RHSA-2017:0190)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for firefox is now available for Red Hat Enterprise Linux 5,
Red Hat Enterprise Linux 6, and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 45.7.0 ESR.

Security Fix(es) :

* Multiple flaws were found in the processing of malformed web
content. A web page containing malicious content could cause Firefox
to crash or, potentially, execute arbitrary code with the privileges
of the user running Firefox. (CVE-2017-5373, CVE-2017-5375,
CVE-2017-5376, CVE-2017-5378, CVE-2017-5380, CVE-2017-5383,
CVE-2017-5386, CVE-2017-5390, CVE-2017-5396)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Jann Horn, Muneaki Nishimura, Nils,
Armin Razmjou, Christian Holler, Gary Kwong, Andre Bargull, Jan de
Mooij, Tom Schuster, and Oriol, Rh0, Nicolas Gregoire, and Jerri Rice
as the original reporters."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-5373.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-5375.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-5376.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-5378.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-5380.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-5383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-5386.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-5390.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-5396.html"
  );
  # https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox-esr/#
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b5eaff4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0190.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or firefox-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/26");
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
if (! ereg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:0190";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"firefox-45.7.0-1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"firefox-45.7.0-1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"firefox-45.7.0-1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"firefox-debuginfo-45.7.0-1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"firefox-debuginfo-45.7.0-1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"firefox-debuginfo-45.7.0-1.el5_11")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"firefox-45.7.0-1.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"firefox-45.7.0-1.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"firefox-45.7.0-1.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"firefox-debuginfo-45.7.0-1.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"firefox-debuginfo-45.7.0-1.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"firefox-debuginfo-45.7.0-1.el6_8")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"firefox-45.7.0-1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"firefox-45.7.0-1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"firefox-45.7.0-1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"firefox-debuginfo-45.7.0-1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"firefox-debuginfo-45.7.0-1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"firefox-debuginfo-45.7.0-1.el7_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo");
  }
}
