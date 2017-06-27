#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0668. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65651);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2012-2677");
  script_xref(name:"RHSA", value:"2013:0668");

  script_name(english:"RHEL 5 / 6 : boost (RHSA-2013:0668)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated boost packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The boost packages provide free, peer-reviewed, portable C++ source
libraries with emphasis on libraries which work well with the C++
Standard Library.

A flaw was found in the way the ordered_malloc() routine in Boost
sanitized the 'next_size' and 'max_size' parameters when allocating
memory. If an application used the Boost C++ libraries for memory
allocation, and performed memory allocation based on user-supplied
input, an attacker could use this flaw to crash the application or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2012-2677)

All users of boost are advised to upgrade to these updated packages,
which contain a backported patch to fix this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2677.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0668.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-date-time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-graph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-graph-mpich2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-graph-openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-iostreams");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-mpich2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-mpich2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-mpich2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-openmpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-openmpi-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-program-options");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-regex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-serialization");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-signals");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-thread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:boost-wave");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/22");
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
  rhsa = "RHSA-2013:0668";
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
  if (rpm_check(release:"RHEL5", reference:"boost-1.33.1-16.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"boost-debuginfo-1.33.1-16.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", reference:"boost-devel-1.33.1-16.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"boost-doc-1.33.1-16.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"boost-doc-1.33.1-16.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"boost-doc-1.33.1-16.el5_9")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"boost-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"boost-date-time-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"boost-debuginfo-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-devel-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"boost-devel-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-devel-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-doc-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"boost-doc-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-doc-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"boost-filesystem-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"boost-graph-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-graph-mpich2-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-graph-mpich2-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-graph-openmpi-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-graph-openmpi-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"boost-iostreams-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-math-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"boost-math-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-math-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-mpich2-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-mpich2-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-mpich2-devel-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-mpich2-devel-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-mpich2-python-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-mpich2-python-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-openmpi-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-openmpi-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-openmpi-devel-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-openmpi-devel-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-openmpi-python-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-openmpi-python-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"boost-program-options-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-python-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"boost-python-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-python-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"boost-regex-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"boost-serialization-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"boost-signals-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"boost-static-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"boost-static-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"boost-static-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"boost-system-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"boost-test-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"boost-thread-1.41.0-15.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"boost-wave-1.41.0-15.el6_4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "boost / boost-date-time / boost-debuginfo / boost-devel / boost-doc / etc");
  }
}
