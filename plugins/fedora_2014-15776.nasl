#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-15776.
#

include("compat.inc");

if (description)
{
  script_id(79783);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 22:14:43 $");

  script_xref(name:"FEDORA", value:"2014-15776");

  script_name(english:"Fedora 21 : jenkins-external-monitor-job-plugin-1.4-1.fc21 / etc (2014-15776)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This big update fixes several security vulnerabilities [1] as well as
few packaging bugs.

[1]:
https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory
+2014-10-01

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1163695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1165086"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145694.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b526e3df"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145695.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?574b0714"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145696.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfca0f10"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145697.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0b0e506"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145698.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b00c6001"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145699.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?723323d7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145700.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f9bb0cd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145701.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab651a5e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145702.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d499fc1f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145703.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a68f590"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145704.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b96c43"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145705.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?767a75d4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145706.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38017e4e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145707.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29d6656d"
  );
  # https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2014-10-01
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1236c16f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-ant-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-credentials-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-external-monitor-job-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-icon-shim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-javadoc-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-junit-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-mailer-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-matrix-project-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-ssh-credentials-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-ssh-slaves-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-winstone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:stapler");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"jenkins-1.590-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"jenkins-ant-plugin-1.2-3.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"jenkins-credentials-plugin-1.18-2.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"jenkins-external-monitor-job-plugin-1.4-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"jenkins-icon-shim-1.0.4-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"jenkins-javadoc-plugin-1.3-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"jenkins-junit-plugin-1.2-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"jenkins-mailer-plugin-1.12-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"jenkins-matrix-project-plugin-1.4-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"jenkins-remoting-2.48-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"jenkins-ssh-credentials-plugin-1.10-3.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"jenkins-ssh-slaves-plugin-1.9-2.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"jenkins-winstone-2.8-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"stapler-1.233-1.fc21")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jenkins / jenkins-ant-plugin / jenkins-credentials-plugin / etc");
}
