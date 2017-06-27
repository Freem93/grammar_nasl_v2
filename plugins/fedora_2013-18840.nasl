#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-18840.
#

include("compat.inc");

if (description)
{
  script_id(70815);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/19 21:37:38 $");

  script_cve_id("CVE-2013-4409", "CVE-2013-4410", "CVE-2013-4411");
  script_bugtraq_id(63022, 63023, 63029);
  script_xref(name:"FEDORA", value:"2013-18840");

  script_name(english:"Fedora 20 : ReviewBoard-1.7.16-2.fc20 / python-djblets-0.7.21-1.fc20 (2013-18840)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Review Board 1.6.19 and 1.7.15 fix a few issues in the API where users
could access certain data they should not have been able to access, if
using the Local Sites feature, invite-only groups, or private
repositories. It also fixes cases with invite-only groups where the
group name and list of private review requests would show up on some
pages (though the review requests themselves were not accessible).

These issues do not affect most of the installations out there, but we
strongly recommend upgrading anyway. There are no known cases of
anyone exploiting these bugs, and in fact we discovered these
internally while building new tools to test for security
vulnerabilities in our codebase.

There are also some other bug fixes, and important changes needed for
extensions that provide their own REST APIs.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1016596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1016599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1016601"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-November/120619.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96c1a5de"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-November/120620.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cbb2d00e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ReviewBoard and / or python-djblets packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ReviewBoard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-djblets");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/11");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"ReviewBoard-1.7.16-2.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"python-djblets-0.7.21-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ReviewBoard / python-djblets");
}
