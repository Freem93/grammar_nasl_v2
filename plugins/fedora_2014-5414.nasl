#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-5414.
#

include("compat.inc");

if (description)
{
  script_id(73777);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 22:32:18 $");

  script_cve_id("CVE-2014-1517");
  script_bugtraq_id(66984);
  script_xref(name:"FEDORA", value:"2014-5414");

  script_name(english:"Fedora 19 : bugzilla-4.2.9-1.fc19 (2014-5414)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Previous versions of bugzilla had the following security issues :

  - The login form had no CSRF protection, meaning that an
    attacker could force the victim to log in using the
    attacker's credentials.

  - Dangerous control characters can be inserted into
    Bugzilla, notably into bug comments, which can then be
    used to execute local commands.

The first issue has the CVE number CVE-2014-1517. Please see
http://www.bugzilla.org/security/4.0.11/ for all the gory details.

Both issues were fixed in 4.2.8 but it introduced a regression in bug
commenting that was fixed in 4.2.9.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.bugzilla.org/security/4.0.11/"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-April/132281.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6290efd1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bugzilla package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC19", reference:"bugzilla-4.2.9-1.fc19")) flag++;


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