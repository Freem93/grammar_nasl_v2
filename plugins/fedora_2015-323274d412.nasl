#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-323274d412.
#

include("compat.inc");

if (description)
{
  script_id(89201);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/04 16:00:57 $");

  script_cve_id("CVE-2015-8213");
  script_xref(name:"FEDORA", value:"2015-323274d412");

  script_name(english:"Fedora 22 : python-django-1.8.7-1.fc22 (2015-323274d412)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to 1.8.7 , fixing CVE-2015-8213 (rhbz#1285278) ---- python-
django-1.8.4-1.fc22 - Do not install bash completion for python
executables (Ville Skytta, rhbz#1253076) - CVE-2015-5963
Denial-of-service possibility in logout() view by filling session
store (rhbz#1254911) - CVE-2015-5964 Denial- of-service possibility in
logout() view by filling session store (rhbz#1252891)
python-django-1.8.4-1.fc23 - Do not install bash completion for python
executables (Ville Skytta, rhbz#1253076) - CVE-2015-5963 Denial-of-
service possibility in logout() view by filling session store
(rhbz#1254911) - CVE-2015-5964 Denial-of-service possibility in
logout() view by filling session store (rhbz#1252891)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1285278"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-December/174770.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac0a4ac4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-django package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"python-django-1.8.7-1.fc22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-django");
}
