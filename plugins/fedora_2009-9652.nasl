#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-9652.
#

include("compat.inc");

if (description)
{
  script_id(40996);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/11 13:16:07 $");

  script_cve_id("CVE-2009-2629");
  script_bugtraq_id(36384);
  script_xref(name:"FEDORA", value:"2009-9652");

  script_name(english:"Fedora 10 : nginx-0.7.62-1.fc10 (2009-9652)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Sep 14 2009 Jeremy Hinegardner <jeremy at
    hinegardner dot org> - 0.7.62-1

    - update to 0.7.62

    - fixes CVE-2009-2629

    - Sun Aug 2 2009 Jeremy Hinegardner <jeremy at
      hinegardner dot org> - 0.7.61-1

    - update to new stable 0.7.61

    - remove third-party module

    - Sat Apr 11 2009 Jeremy Hinegardner <jeremy at
      hinegardner dot org> 0.6.36-1

    - update to 0.6.36

    - Wed Feb 25 2009 Fedora Release Engineering <rel-eng at
      lists.fedoraproject.org> - 0.6.35-3

    - Rebuilt for
      https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

    - Thu Feb 19 2009 Jeremy Hinegardner <jeremy at
      hinegardner dot org> - 0.6.35-2

    - rebuild

    - Thu Feb 19 2009 Jeremy Hinegardner <jeremy at
      hinegardner dot org> - 0.6.35-1

    - update to 0.6.35

    - Sat Jan 17 2009 Tomas Mraz <tmraz at redhat.com> -
      0.6.34-2

    - rebuild with new openssl

    - Tue Dec 30 2008 Jeremy Hinegardner <jeremy at
      hinegardner dot org> - 0.6.34-1

    - update to 0.6.34

    - Thu Dec 4 2008 Michael Schwendt <mschwendt at
      fedoraproject.org> - 0.6.33-2

    - Fix inclusion of /usr/share/nginx tree => no unowned
      directories.

    - Sun Nov 23 2008 Jeremy Hinegardner <jeremy at
      hinegardner dot org> - 0.6.33-1

    - update to 0.6.33

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=523105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-September/029250.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b45ba97d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nginx package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nginx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/16");
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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"nginx-0.7.62-1.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx");
}