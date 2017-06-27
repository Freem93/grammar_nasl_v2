#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1983. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80011);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 15:51:00 $");

  script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8094", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102", "CVE-2014-8103");
  script_osvdb_id(115603, 115604, 115605, 115606, 115607, 115608, 115609, 115610, 115611, 115612, 115613, 115614, 115615);
  script_xref(name:"RHSA", value:"2014:1983");

  script_name(english:"RHEL 6 / 7 : xorg-x11-server (RHSA-2014:1983)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11-server packages that fix multiple security issues are
now available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

Multiple integer overflow flaws and out-of-bounds write flaws were
found in the way the X.Org server calculated memory requirements for
certain X11 core protocol and GLX extension requests. A malicious,
authenticated client could use either of these flaws to crash the
X.Org server or, potentially, execute arbitrary code with root
privileges. (CVE-2014-8092, CVE-2014-8093, CVE-2014-8098)

It was found that the X.Org server did not properly handle SUN-DES-1
(Secure RPC) authentication credentials. A malicious, unauthenticated
client could use this flaw to crash the X.Org server by submitting a
specially crafted authentication request. (CVE-2014-8091)

Multiple out-of-bounds access flaws were found in the way the X.Org
server calculated memory requirements for certain requests. A
malicious, authenticated client could use either of these flaws to
crash the X.Org server, or leak memory contents to the client.
(CVE-2014-8097)

An integer overflow flaw was found in the way the X.Org server
calculated memory requirements for certain DRI2 extension requests. A
malicious, authenticated client could use this flaw to crash the X.Org
server. (CVE-2014-8094)

Multiple out-of-bounds access flaws were found in the way the X.Org
server calculated memory requirements for certain requests. A
malicious, authenticated client could use either of these flaws to
crash the X.Org server. (CVE-2014-8095, CVE-2014-8096, CVE-2014-8099,
CVE-2014-8100, CVE-2014-8101, CVE-2014-8102, CVE-2014-8103)

All xorg-x11-server users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8091.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8092.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8096.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8097.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8098.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8099.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8100.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8101.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8102.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-8103.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.x.org/wiki/Development/Security/Advisory-2014-12-09/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1983.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2014:1983";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-Xdmx-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xorg-x11-server-Xdmx-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-Xdmx-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-Xephyr-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xorg-x11-server-Xephyr-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-Xephyr-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-Xnest-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xorg-x11-server-Xnest-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-Xnest-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-Xorg-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-Xorg-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-Xvfb-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xorg-x11-server-Xvfb-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-Xvfb-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-common-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xorg-x11-server-common-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-common-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-debuginfo-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xorg-x11-server-debuginfo-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-debuginfo-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xorg-x11-server-devel-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xorg-x11-server-devel-1.15.0-25.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"xorg-x11-server-source-1.15.0-25.el6_6")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xdmx-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xdmx-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xephyr-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xephyr-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xnest-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xnest-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xorg-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-Xvfb-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-Xvfb-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-common-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-common-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-server-debuginfo-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"xorg-x11-server-debuginfo-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-debuginfo-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"xorg-x11-server-devel-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"xorg-x11-server-devel-1.15.0-7.el7_0.3")) flag++;

  if (rpm_check(release:"RHEL7", reference:"xorg-x11-server-source-1.15.0-7.el7_0.3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xephyr / etc");
  }
}
