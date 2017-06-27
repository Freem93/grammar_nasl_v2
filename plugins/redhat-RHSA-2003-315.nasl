#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2003:315. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12431);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/28 17:44:43 $");

  script_cve_id("CVE-2003-0858");
  script_osvdb_id(6594, 55381, 55382);
  script_xref(name:"RHSA", value:"2003:315");

  script_name(english:"RHEL 3 : quagga (RHSA-2003:315)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Quagga packages that close a locally-exploitable denial of
service vulnerability are now available.

Quagga is an open source implementation of TCP/IP routing software.

Herbert Xu reported that Quagga can accept spoofed messages sent on
the kernel netlink interface by other users on the local machine. This
could lead to a local denial of service attack. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2003-0858 to this issue.

Users of Quagga should upgrade to these erratum packages, which
contain a patch that checks that netlink messages actually came from
the kernel. This erratum also includes quagga-devel and quagga-contrib
packages which were not originally shipped with Red Hat Enterprise
Linux 3."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0858.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2003-315.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected quagga, quagga-contrib and / or quagga-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quagga-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2003:315";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL3", reference:"quagga-0.96.2-8.3E")) flag++;
  if (rpm_check(release:"RHEL3", reference:"quagga-contrib-0.96.2-8.3E")) flag++;
  if (rpm_check(release:"RHEL3", reference:"quagga-devel-0.96.2-8.3E")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
