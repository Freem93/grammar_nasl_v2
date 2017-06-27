#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0066. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24833);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/29 15:35:20 $");

  script_cve_id("CVE-2007-0456", "CVE-2007-0457", "CVE-2007-0458", "CVE-2007-0459");
  script_osvdb_id(33073, 33074, 33075, 33076);
  script_xref(name:"RHSA", value:"2007:0066");

  script_name(english:"RHEL 2.1 / 3 / 4 / 5 : wireshark (RHSA-2007:0066)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New Wireshark packages that fix various security vulnerabilities are
now available. Wireshark was previously known as Ethereal.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Wireshark is a program for monitoring network traffic.

Several denial of service bugs were found in Wireshark's LLT, IEEE
802.11, http, and tcp protocol dissectors. It was possible for
Wireshark to crash or stop responding if it read a malformed packet
off the network. (CVE-2007-0456, CVE-2007-0457, CVE-2007-0458,
CVE-2007-0459)

Users of Wireshark should upgrade to these updated packages containing
Wireshark version 0.99.5, which is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0456.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0457.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0458.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-0459.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0066.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark and / or wireshark-gnome packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0066";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"wireshark-0.99.5-AS21.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"wireshark-gnome-0.99.5-AS21.3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"wireshark-0.99.5-EL3.1")) flag++;
  if (rpm_check(release:"RHEL3", reference:"wireshark-gnome-0.99.5-EL3.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"wireshark-0.99.5-EL4.1")) flag++;
  if (rpm_check(release:"RHEL4", reference:"wireshark-gnome-0.99.5-EL4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"wireshark-0.99.5-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"wireshark-0.99.5-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"wireshark-0.99.5-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"wireshark-gnome-0.99.5-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"wireshark-gnome-0.99.5-1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"wireshark-gnome-0.99.5-1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-gnome");
  }
}
