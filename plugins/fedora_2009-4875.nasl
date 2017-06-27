#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-4875.
#

include("compat.inc");

if (description)
{
  script_id(38749);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:21:55 $");

  script_cve_id("CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1580", "CVE-2009-1581");
  script_xref(name:"FEDORA", value:"2009-4875");

  script_name(english:"Fedora 11 : squirrelmail-1.4.18-1.fc11 (2009-4875)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue May 12 2009 Michal Hlavinka <mhlavink at redhat.com>
    - 1.4.18-1

    - updated to 1.4.18

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=500356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=500358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=500360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=500363"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-May/023473.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ce447f4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(79, 94, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"squirrelmail-1.4.18-1.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squirrelmail");
}
