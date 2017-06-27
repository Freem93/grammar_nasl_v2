#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1259. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62070);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/05 16:17:29 $");

  script_cve_id("CVE-2011-3323", "CVE-2011-3324", "CVE-2011-3325", "CVE-2011-3326", "CVE-2011-3327", "CVE-2012-0249", "CVE-2012-0250", "CVE-2012-0255", "CVE-2012-1820");
  script_bugtraq_id(49784, 52531, 53775);
  script_osvdb_id(75728, 75729, 75730, 75731, 75732, 80113, 80114, 82692);
  script_xref(name:"RHSA", value:"2012:1259");

  script_name(english:"RHEL 6 : quagga (RHSA-2012:1259)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated quagga packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Quagga is a TCP/IP based routing software suite. The Quagga bgpd
daemon implements the BGP (Border Gateway Protocol) routing protocol.
The Quagga ospfd and ospf6d daemons implement the OSPF (Open Shortest
Path First) routing protocol.

A heap-based buffer overflow flaw was found in the way the bgpd daemon
processed malformed Extended Communities path attributes. An attacker
could send a specially crafted BGP message, causing bgpd on a target
system to crash or, possibly, execute arbitrary code with the
privileges of the user running bgpd. The UPDATE message would have to
arrive from an explicitly configured BGP peer, but could have
originated elsewhere in the BGP network. (CVE-2011-3327)

A stack-based buffer overflow flaw was found in the way the ospf6d
daemon processed malformed Link State Update packets. An OSPF router
could use this flaw to crash ospf6d on an adjacent router.
(CVE-2011-3323)

A flaw was found in the way the ospf6d daemon processed malformed link
state advertisements. An OSPF neighbor could use this flaw to crash
ospf6d on a target system. (CVE-2011-3324)

A flaw was found in the way the ospfd daemon processed malformed Hello
packets. An OSPF neighbor could use this flaw to crash ospfd on a
target system. (CVE-2011-3325)

A flaw was found in the way the ospfd daemon processed malformed link
state advertisements. An OSPF router in the autonomous system could
use this flaw to crash ospfd on a target system. (CVE-2011-3326)

An assertion failure was found in the way the ospfd daemon processed
certain Link State Update packets. An OSPF router could use this flaw
to cause ospfd on an adjacent router to abort. (CVE-2012-0249)

A buffer overflow flaw was found in the way the ospfd daemon processed
certain Link State Update packets. An OSPF router could use this flaw
to crash ospfd on an adjacent router. (CVE-2012-0250)

Two flaws were found in the way the bgpd daemon processed certain BGP
OPEN messages. A configured BGP peer could cause bgpd on a target
system to abort via a specially crafted BGP OPEN message.
(CVE-2012-0255, CVE-2012-1820)

Red Hat would like to thank CERT-FI for reporting CVE-2011-3327,
CVE-2011-3323, CVE-2011-3324, CVE-2011-3325, and CVE-2011-3326; and
the CERT/CC for reporting CVE-2012-0249, CVE-2012-0250, CVE-2012-0255,
and CVE-2012-1820. CERT-FI acknowledges Riku Hietamaki, Tuomo Untinen
and Jukka Taimisto of the Codenomicon CROSS project as the original
reporters of CVE-2011-3327, CVE-2011-3323, CVE-2011-3324,
CVE-2011-3325, and CVE-2011-3326. The CERT/CC acknowledges Martin
Winter at OpenSourceRouting.org as the original reporter of
CVE-2012-0249, CVE-2012-0250, and CVE-2012-0255, and Denis Ovsienko as
the original reporter of CVE-2012-1820.

Users of quagga should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the bgpd, ospfd, and ospf6d daemons will be
restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3323.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3324.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3325.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3326.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3327.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0249.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0250.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0255.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1820.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1259.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quagga-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quagga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/13");
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
  rhsa = "RHSA-2012:1259";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"quagga-0.99.15-7.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"quagga-0.99.15-7.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"quagga-0.99.15-7.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"quagga-contrib-0.99.15-7.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"quagga-contrib-0.99.15-7.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"quagga-contrib-0.99.15-7.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"quagga-debuginfo-0.99.15-7.el6_3.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"quagga-devel-0.99.15-7.el6_3.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga / quagga-contrib / quagga-debuginfo / quagga-devel");
  }
}
