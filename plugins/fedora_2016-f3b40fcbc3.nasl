#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-f3b40fcbc3.
#

include("compat.inc");

if (description)
{
  script_id(92206);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/03/06 14:38:26 $");

  script_cve_id("CVE-2016-3101", "CVE-2016-3102");
  script_xref(name:"FEDORA", value:"2016-f3b40fcbc3");

  script_name(english:"Fedora 24 : jenkins / jenkins-credentials-plugin / jenkins-junit-plugin / etc (2016-f3b40fcbc3)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fix for CVE-2016-3102. Update to 1.651.1. Fix dangling
symlink (rhbz#1330472)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-f3b40fcbc3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-credentials-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-junit-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-mailer-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jenkins-script-security-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:owasp-java-html-sanitizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:stapler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tiger-types");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"jenkins-1.651.1-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"jenkins-credentials-plugin-1.27-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"jenkins-junit-plugin-1.12-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"jenkins-mailer-plugin-1.17-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"jenkins-remoting-2.57-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"jenkins-script-security-plugin-1.18.1-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"owasp-java-html-sanitizer-20160422.1-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"stapler-1.242-1.fc24")) flag++;
if (rpm_check(release:"FC24", reference:"tiger-types-2.2-1.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jenkins / jenkins-credentials-plugin / jenkins-junit-plugin / etc");
}
