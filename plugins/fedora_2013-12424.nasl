#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-12424.
#

include("compat.inc");

if (description)
{
  script_id(68891);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/09 15:36:32 $");

  script_cve_id("CVE-2013-2138");
  script_bugtraq_id(60313);
  script_xref(name:"FEDORA", value:"2013-12424");

  script_name(english:"Fedora 18 : gallery3-3.0.9-1.fc18 (2013-12424)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes for CVE-2013-2240, CVE-2013-2241.

A security flaw was found in the way flowplayer SWF file handling
functionality of Gallery version 3, an open source project with the
goal to develop and support leading photo sharing web application
solutions, processed certain URL fragments passed to this file
(certain URL fragments were not stripped properly when these files
were called via direct URL request(s)). A remote attacker could use
this flaw to conduct replay attacks.

Multiple information exposure flaws were found in the way data rest
core module of Gallery version 3, an open source project with the goal
to develop and support leading photo sharing web application
solutions, used to previously restrict access to certain items of the
photo album. A remote attacker, valid Gallery 3 user, could use this
flaw to possibly obtain sensitive information (file, resize or thumb
path of the item in question).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=981218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=981219"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/111705.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb4b5f22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gallery3 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/16");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"gallery3-3.0.9-1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gallery3");
}
