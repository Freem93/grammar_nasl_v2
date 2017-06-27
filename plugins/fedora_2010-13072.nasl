#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-13072.
#

include("compat.inc");

if (description)
{
  script_id(48913);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/11 13:16:08 $");

  script_cve_id("CVE-2010-2756", "CVE-2010-2757", "CVE-2010-2758", "CVE-2010-2759");
  script_bugtraq_id(42275);
  script_osvdb_id(67196, 67197, 67198, 67199);
  script_xref(name:"FEDORA", value:"2010-13072");

  script_name(english:"Fedora 12 : bugzilla-3.4.8-1.fc12 (2010-13072)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Aug 19 2010 Emmanuel Seyman <emmanuel.seyman at
    club-internet.fr> - 3.4.8-1

    - Update to 3.4.8 (#623426, #615331)

    - Only run checksetup if /etc/bugzilla/localconfig does
      not exist (#610210)

    - Add bugzilla-contrib to Requires (#610198)

    - Remove mod_perl from the requirements (#600924)

    - Fri Jun 25 2010 Emmanuel Seyman <emmanuel.seyman at
      club-internet.fr> - 3.4.7-1

    - Update to 3.4.7 (CVE-2010-1204)

    - Mon Feb 1 2010 Emmanuel Seyman <emmanuel.seyman at
      club-internet.fr> - 3.4.5-1

    - Update to 3.4.5 (CVE-2009-3989, CVE-2009-3387)

    - Remove bugzilla-EL5-perl-versions.patch which is
      EPEL-specific

    - Thu Nov 19 2009 Emmanuel Seyman <emmanuel.seyman at
      club-internet.fr> - 3.4.4-1

    - Update to 3.4.4 (CVE-2009-3386)

    - Wed Nov 11 2009 Emmanuel Seyman <emmanuel.seyman at
      club-internet.fr> - 3.4.3-1

    - Update to 3.4.3 (fixes memory leak issues)

    - Add perl(Digest::SHA) in the Requires

    - Specify Perl module versions in the Requires (fixes
      #524309)

    - Add an alias to make $webdotdir a working path (fixes
      #458848)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=623423"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-August/046534.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48035cf2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bugzilla package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC12", reference:"bugzilla-3.4.8-1.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bugzilla");
}
