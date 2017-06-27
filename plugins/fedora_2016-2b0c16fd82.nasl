#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-2b0c16fd82.
#

include("compat.inc");

if (description)
{
  script_id(93260);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/18 16:42:54 $");

  script_cve_id("CVE-2016-3092");
  script_xref(name:"FEDORA", value:"2016-2b0c16fd82");

  script_name(english:"Fedora 24 : 1:tomcat (2016-2b0c16fd82)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This updates includes a rebase from tomcat 8.0.32 up to 8.0.36 to
resolve :

  - rhbz#1349469 CVE-2016-3092 tomcat: Usage of vulnerable
    FileUpload package can result in denial of service

and also includes the following bug fixes :

  - rhbz#1341850 tomcat-jsvc.service has TOMCAT_USER value
    hard-coded

  - rhbz#1341853 rpm -V tomcat fails on
    /var/log/tomcat/catalina.out

  - rhbz#1347835 The security manager doesn't work correctly
    (JSPs cannot be compiled)

  - rhbz#1347864 The systemd service unit does not allow
    tomcat to shut down gracefully

  - rhbz#1357428 Tomcat 8.0.32 breaks deploy for candlepin.

  - rhbz#1359737 Missing maven depmap for the following
    artifacts: org.apache.tomcat:tomcat-websocket,
    org.apache.tomcat:tomcat-websocket-api

  - rhbz#1363884 The tomcat-tool-wrapper script is broken

  - rhbz#1364056 The command tomcat-digest doesn't work

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-2b0c16fd82"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 1:tomcat package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:tomcat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC24", reference:"tomcat-8.0.36-2.fc24", epoch:"1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:tomcat");
}
