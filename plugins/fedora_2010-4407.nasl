#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-4407.
#

include("compat.inc");

if (description)
{
  script_id(47361);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 21:38:17 $");

  script_cve_id("CVE-2009-3736");
  script_bugtraq_id(37128);
  script_osvdb_id(60522);
  script_xref(name:"FEDORA", value:"2010-4407");

  script_name(english:"Fedora 12 : hamlib-1.2.10-2.fc12 (2010-4407)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Mar 11 2010 Lucian Langa <cooly at gnome.eu.org> -
    1.2.10-2

    - kill rpath

    - misc cleanups

    - use system ltdl (#563975)

    - Sat Nov 7 2009 Lucian Langa <cooly at gnome.eu.org> -
      1.2.10-1

    - new upstream release

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=537941"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-April/038467.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a32cdc7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hamlib package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:hamlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"hamlib-1.2.10-2.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hamlib");
}
