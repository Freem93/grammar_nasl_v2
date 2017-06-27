#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0858. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55012);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2009-2625");
  script_bugtraq_id(35958);
  script_osvdb_id(56984);
  script_xref(name:"RHSA", value:"2011:0858");

  script_name(english:"RHEL 6 : xerces-j2 (RHSA-2011:0858)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xerces-j2 packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The xerces-j2 packages provide the Apache Xerces2 Java Parser, a
high-performance XML parser. A Document Type Definition (DTD) defines
the legal syntax (and also which elements can be used) for certain
types of files, such as XML files.

A flaw was found in the way the Apache Xerces2 Java Parser processed
the SYSTEM identifier in DTDs. A remote attacker could provide a
specially crafted XML file, which once parsed by an application using
the Apache Xerces2 Java Parser, would lead to a denial of service
(application hang due to excessive CPU use). (CVE-2009-2625)

Users should upgrade to these updated packages, which contain a
backported patch to correct this issue. Applications using the Apache
Xerces2 Java Parser must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2625.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0858.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-javadoc-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-javadoc-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-javadoc-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-javadoc-xni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-scripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2011:0858";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-debuginfo-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-debuginfo-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-debuginfo-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-demo-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-demo-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-demo-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-javadoc-apis-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-javadoc-apis-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-javadoc-apis-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-javadoc-impl-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-javadoc-impl-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-javadoc-impl-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-javadoc-other-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-javadoc-other-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-javadoc-other-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-javadoc-xni-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-javadoc-xni-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-javadoc-xni-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"xerces-j2-scripts-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"xerces-j2-scripts-2.7.1-12.6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"xerces-j2-scripts-2.7.1-12.6.el6_0")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xerces-j2 / xerces-j2-debuginfo / xerces-j2-demo / etc");
  }
}
