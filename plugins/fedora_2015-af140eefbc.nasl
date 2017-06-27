#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-af140eefbc.
#

include("compat.inc");

if (description)
{
  script_id(89370);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/18 16:42:53 $");

  script_cve_id("CVE-2015-5330");
  script_xref(name:"FEDORA", value:"2015-af140eefbc");

  script_name(english:"Fedora 22 : libldb-1.1.24-1.fc22 / libtalloc-2.1.5-2.fc22 / libtdb-1.3.8-1.fc22 / etc (2015-af140eefbc)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes CVE-2015-5330

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1292070"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-December/174116.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c97bbfb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-December/174117.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f2bbd2d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-December/174118.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4082efa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-December/174119.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9609bf47"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libtalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libtdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libtevent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/18");
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
if (rpm_check(release:"FC22", reference:"libldb-1.1.24-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"libtalloc-2.1.5-2.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"libtdb-1.3.8-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"libtevent-0.9.26-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libldb / libtalloc / libtdb / libtevent");
}
