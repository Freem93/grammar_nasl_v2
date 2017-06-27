#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0785. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50077);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/01/04 15:51:48 $");

  script_cve_id("CVE-2007-4826", "CVE-2010-2948");
  script_bugtraq_id(25634, 42635);
  script_osvdb_id(67394);
  script_xref(name:"RHSA", value:"2010:0785");

  script_name(english:"RHEL 4 / 5 : quagga (RHSA-2010:0785)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated quagga packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Quagga is a TCP/IP based routing software suite. The Quagga bgpd
daemon implements the BGP (Border Gateway Protocol) routing protocol.

A stack-based buffer overflow flaw was found in the way the Quagga
bgpd daemon processed certain BGP Route Refresh (RR) messages. A
configured BGP peer could send a specially crafted BGP message,
causing bgpd on a target system to crash or, possibly, execute
arbitrary code with the privileges of the user running bgpd.
(CVE-2010-2948)

Note: On Red Hat Enterprise Linux 5 it is not possible to exploit
CVE-2010-2948 to run arbitrary code as the overflow is blocked by
FORTIFY_SOURCE.

Multiple NULL pointer dereference flaws were found in the way the
Quagga bgpd daemon processed certain specially crafted BGP messages. A
configured BGP peer could crash bgpd on a target system via specially
crafted BGP messages. (CVE-2007-4826)

Users of quagga should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the bgpd daemon must be restarted for the update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4826.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2948.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0785.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected quagga, quagga-contrib and / or quagga-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quagga-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0785";
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
  if (rpm_check(release:"RHEL4", reference:"quagga-0.98.3-4.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"quagga-contrib-0.98.3-4.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"quagga-devel-0.98.3-4.el4_8.1")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"quagga-0.98.6-5.el5_5.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"quagga-0.98.6-5.el5_5.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"quagga-0.98.6-5.el5_5.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"quagga-contrib-0.98.6-5.el5_5.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"quagga-contrib-0.98.6-5.el5_5.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"quagga-contrib-0.98.6-5.el5_5.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"quagga-devel-0.98.6-5.el5_5.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga / quagga-contrib / quagga-devel");
  }
}
