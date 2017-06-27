#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0020. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96312);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/13 20:45:10 $");

  script_cve_id("CVE-2016-9634", "CVE-2016-9635", "CVE-2016-9636", "CVE-2016-9807", "CVE-2016-9808");
  script_osvdb_id(147688, 148101);
  script_xref(name:"RHSA", value:"2017:0020");

  script_name(english:"RHEL 7 : gstreamer1-plugins-good (RHSA-2017:0020)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for gstreamer1-plugins-good is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

GStreamer is a streaming media framework based on graphs of filters
which operate on media data. The gstreamer1-plugins-good packages
contain a collection of well-supported plug-ins of good quality and
under the LGPL license.

Security Fix(es) :

* Multiple flaws were discovered in GStreamer's FLC/FLI/FLX media file
format decoding plug-in. A remote attacker could use these flaws to
cause an application using GStreamer to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2016-9634, CVE-2016-9635, CVE-2016-9636,
CVE-2016-9808)

* An invalid memory read access flaw was found in GStreamer's
FLC/FLI/FLX media file format decoding plug-in. A remote attacker
could use this flaw to cause an application using GStreamer to crash.
(CVE-2016-9807)

Note: This update removes the vulnerable FLC/FLI/FLX plug-in."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-9634.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-9635.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-9636.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-9807.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-9808.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0020.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected gstreamer1-plugins-good and / or
gstreamer1-plugins-good-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstreamer1-plugins-good-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/05");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:0020";
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
  if (rpm_check(release:"RHEL7", reference:"gstreamer1-plugins-good-1.4.5-3.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"gstreamer1-plugins-good-1.4.5-3.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"gstreamer1-plugins-good-1.4.5-3.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gstreamer1-plugins-good-debuginfo-1.4.5-3.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"gstreamer1-plugins-good-debuginfo-1.4.5-3.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"gstreamer1-plugins-good-debuginfo-1.4.5-3.el7_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer1-plugins-good / gstreamer1-plugins-good-debuginfo");
  }
}
