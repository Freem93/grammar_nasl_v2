#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-16410.
#

include("compat.inc");

if (description)
{
  script_id(70056);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/09 15:36:32 $");

  script_bugtraq_id(62410, 62411, 62412);
  script_xref(name:"FEDORA", value:"2013-16410");

  script_name(english:"Fedora 20 : moodle-2.5.2-1.fc20 (2013-16410)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Moodle upstream has released upstream 2.3.9, 2.4.6, and 2.5.2 
versions :

http://docs.moodle.org/dev/Moodle_2.3.9_release_notes
http://docs.moodle.org/dev/Moodle_2.4.6_release_notes
http://docs.moodle.org/dev/Moodle_2.5.2_release_notes

These releases contain unspecified security fixes, the nature of which
will be public next week; as per the upstream announcements :

'A number of security related issues were resolved. Details of these
issues will be released after a period of approximately one week to
allow system administrators to safely update to the latest version.'
Update to more recent upstream branch.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://docs.moodle.org/dev/Moodle_2.3.9_release_notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://docs.moodle.org/dev/Moodle_2.4.6_release_notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://docs.moodle.org/dev/Moodle_2.5.2_release_notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1006678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1006679"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-September/116313.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc99cb80"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected moodle package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC20", reference:"moodle-2.5.2-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "moodle");
}
