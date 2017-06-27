#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-10138.
#

include("compat.inc");

if (description)
{
  script_id(67270);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/09 15:36:32 $");

  script_bugtraq_id(60313);
  script_xref(name:"FEDORA", value:"2013-10138");

  script_name(english:"Fedora 18 : gallery3-3.0.8-1.fc18 (2013-10138)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A security flaw was found in the way uploadify and flowplayer SWF
files handling functionality of Gallery version 3, an open source
project with the goal to develop and support leading photo sharing web
application solutions, processed certain URL fragments passed to these
files (certain URL fragments were not stripped properly when these
files were called via direct URL request(s)). A remote attacker could
use this flaw to conduct replay attacks.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://galleryproject.org/gallery_3_0_8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceforge.net/apps/trac/gallery/ticket/2068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceforge.net/apps/trac/gallery/ticket/2070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceforge.net/mailarchive/message.php?msg_id=30925931"
  );
  # https://github.com/gallery/gallery3/commit/12e51694fdc39c752cc439424cf309866f9f914a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efe01ba5"
  );
  # https://github.com/gallery/gallery3/commit/3e5bba2cd4febe8331c0158c11ea418f21c72efa
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3bf624a4"
  );
  # https://github.com/gallery/gallery3/commit/80bb0f2222dd99ed2ce59e804b833bab63cc376a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e882c067"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108942.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68fa7f9b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gallery3 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gallery3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
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
if (rpm_check(release:"FC18", reference:"gallery3-3.0.8-1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gallery3");
}
