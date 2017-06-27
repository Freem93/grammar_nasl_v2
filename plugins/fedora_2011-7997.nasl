#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-7997.
#

include("compat.inc");

if (description)
{
  script_id(55154);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/20 22:15:24 $");

  script_cve_id("CVE-2010-4005");
  script_xref(name:"FEDORA", value:"2011-7997");

  script_name(english:"Fedora 15 : tomboy-1.6.0-1.fc15 (2011-7997)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Version 1.6.0 :

  - Grammar and language fixes (bgo#642156)

    - Changed GetSelectedNotebook from private to public so
      it can be used by add-ins (Robert Nordan)

    - Fix tomboy insecure LD_LIBRARY_PATH (bgo#635614, Luis
      Medinas)

    - Fix CVE-2010-4005 (Luis Medinas). Originally found by
      Ludwig Nussel <lnussel at novell.com>

    - Fix Remove title format from add-ins descriptions
      (bgo#636606, Paul Cutler)

    - Fix Replace Computer Name with Login Name in SSH sync
      setup (bgo#633605, Paul Cutler)

    - Translation Updates: es, br, io, bg, cn, cz, dut, fr,
      gl, de, el, gu, he, hu, in, ja, ko, lv, no, pl, pt,
      ru, sk, sl, sv, th, ug, and zh.

    - Added new translation Luganda (ug).

Packaging changes :

  - The .desktop file is included.

    - For F14, the panel applet is enabled.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=644606"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-June/061561.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23738900"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomboy package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tomboy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"tomboy-1.6.0-1.fc15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomboy");
}
