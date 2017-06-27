#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0250. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64565);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2012-4545");
  script_osvdb_id(88810);
  script_xref(name:"RHSA", value:"2013:0250");

  script_name(english:"RHEL 5 / 6 : elinks (RHSA-2013:0250)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated elinks package that fixes one security issue is now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

ELinks is a text-based web browser. ELinks does not display any
images, but it does support frames, tables, and most other HTML tags.

It was found that ELinks performed client credentials delegation
during the client-to-server GSS security mechanisms negotiation. A
rogue server could use this flaw to obtain the client's credentials
and impersonate that client to other servers that are using GSSAPI.
(CVE-2012-4545)

This issue was discovered by Marko Myllynen of Red Hat.

All ELinks users are advised to upgrade to this updated package, which
contains a backported patch to resolve the issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4545.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0250.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected elinks and / or elinks-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elinks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elinks-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0250";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"elinks-0.11.1-8.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"elinks-0.11.1-8.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"elinks-0.11.1-8.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"elinks-debuginfo-0.11.1-8.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"elinks-debuginfo-0.11.1-8.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"elinks-debuginfo-0.11.1-8.el5_9")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"elinks-0.12-0.21.pre5.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"elinks-0.12-0.21.pre5.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"elinks-0.12-0.21.pre5.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"elinks-debuginfo-0.12-0.21.pre5.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"elinks-debuginfo-0.12-0.21.pre5.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"elinks-debuginfo-0.12-0.21.pre5.el6_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "elinks / elinks-debuginfo");
  }
}
