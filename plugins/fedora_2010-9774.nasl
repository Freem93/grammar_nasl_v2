#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-9774.
#

include("compat.inc");

if (description)
{
  script_id(47552);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/20 21:47:26 $");

  script_cve_id("CVE-2009-3377");
  script_bugtraq_id(36872);
  script_xref(name:"FEDORA", value:"2010-9774");

  script_name(english:"Fedora 13 : libannodex-0.7.3-14.fc13 / libfishsound-0.9.1-5.fc13 / liboggz-1.1.1-1.fc13 / etc (2010-9774)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update upgrades liboggs to version 1.1.1, fixing multiple
security issues: CVE-2009-3377 liboggz: unspecified security fixes
mentioned in MFSA 2009-63 This updates also provides updated
libannodex, mod_annodex, libfishsound, and sonic-visualiser rebuilt
against new liboggz version.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=531770"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-June/042712.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16c3e9e2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-June/042713.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75143ced"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-June/042714.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbd3fc11"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-June/042715.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b060dfc2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-June/042716.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8359e486"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libannodex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libfishsound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:liboggz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mod_annodex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sonic-visualiser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/10");
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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"libannodex-0.7.3-14.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"libfishsound-0.9.1-5.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"liboggz-1.1.1-1.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"mod_annodex-0.2.2-13.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"sonic-visualiser-1.7.2-1.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libannodex / libfishsound / liboggz / mod_annodex / etc");
}
