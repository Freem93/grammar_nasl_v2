#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-14106.
#

include("compat.inc");

if (description)
{
  script_id(69298);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 21:12:41 $");

  script_cve_id("CVE-2013-2160");
  script_xref(name:"FEDORA", value:"2013-14106");

  script_name(english:"Fedora 19 : cxf-2.6.9-1.fc19 / jacorb-2.3.1-8.fc19 / wss4j-1.6.10-1.fc19 (2013-14106)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upgrade of CXF to 2.6.9, fixes CVE-2013-2160.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=929197"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-August/113791.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3cf87d55"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-August/113792.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e74effcb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-August/113793.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c11c1ce"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cxf, jacorb and / or wss4j packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jacorb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wss4j");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"cxf-2.6.9-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"jacorb-2.3.1-8.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"wss4j-1.6.10-1.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cxf / jacorb / wss4j");
}
