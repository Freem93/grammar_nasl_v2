#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-1190.
#

include("compat.inc");

if (description)
{
  script_id(47239);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/11 13:16:08 $");

  script_cve_id("CVE-2010-0787");
  script_bugtraq_id(36363, 36572, 36573, 37992);
  script_xref(name:"FEDORA", value:"2010-1190");

  script_name(english:"Fedora 11 : samba-3.4.5-0.47.fc11 (2010-1190)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Jan 26 2010 Guenther Deschner <gdeschner at
    redhat.com> - 3.4.5-0.47

    - Security Release, fixes CVE-2009-3297

    - resolves: #532940

    - Tue Jan 19 2010 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.5-0.46

    - Update to 3.4.5

    - Thu Jan 7 2010 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.4-0.45

    - Update to 3.4.4

    - Thu Oct 29 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.3-0.44

    - Update to 3.4.3

    - Wed Oct 7 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.2-0.43

    - Fix required talloc version

    - resolves: #527806

    - Thu Oct 1 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.2-0.42

    - Update to 3.4.2

    - Security Release, fixes CVE-2009-2813, CVE-2009-2948
      and CVE-2009-2906

    - Wed Sep 9 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.1.0-41

    - Update to 3.4.1

    - Fri Jul 17 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.0-0.40

    - Fix Bug #6551 (vuid and tid not set in sessionsetupX
      and tconX)

    - Specify required talloc and tdb version for
      BuildRequires

    - Wed Jul 15 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.0-0.39

    - Update to 3.4.0

    - resolves: #510558

    - Fri Jun 19 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.3.5-0.38

    - Fix password expiry calculation in pam_winbind

    - Tue Jun 16 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.3.5-0.37

    - Update to 3.3.5

    - Wed Apr 29 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.3.4-0.36

    - Update to 3.3.4

    - Mon Apr 20 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.3.3-0.35

    - Enable build of idmap_tdb2 for clustered setups

    - Wed Apr 1 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.3.3-0.34

    - Update to 3.3.3

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=532940"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-January/034444.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd3729d4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected samba package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
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
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"samba-3.4.5-0.47.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
