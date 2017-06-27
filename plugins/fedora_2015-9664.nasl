#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-9664.
#

include("compat.inc");

if (description)
{
  script_id(84281);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 23:22:35 $");

  script_xref(name:"FEDORA", value:"2015-9664");

  script_name(english:"Fedora 21 : python-urllib3-1.10.4-3.20150503gita91975b.fc21 / python-requests-2.7.0-1.fc21 (2015-9664)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Inject pyOpenSSL.
https://urllib3.readthedocs.org/en/latest/security.html#insecureplatfo
rmwarning
https://urllib3.readthedocs.org/en/latest/security.html#pyopenssl

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1202077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1222024"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-June/160255.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b518707"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-June/160256.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98378b71"
  );
  # https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8804a539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://urllib3.readthedocs.org/en/latest/security.html#pyopenssl"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-requests and / or python-urllib3 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-urllib3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC21", reference:"python-requests-2.7.0-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"python-urllib3-1.10.4-3.20150503gita91975b.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-requests / python-urllib3");
}
