#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-3283.
#

include("compat.inc");

if (description)
{
  script_id(36077);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/20 13:54:17 $");

  script_cve_id("CVE-2009-1171");
  script_bugtraq_id(34278);
  script_xref(name:"EDB-ID", value:"8297");
  script_xref(name:"FEDORA", value:"2009-3283");

  script_name(english:"Fedora 9 : moodle-1.9.4-6.fc9 (2009-3283)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2009-1171: The TeX filter in Moodle 1.6 before 1.6.9+, 1.7 before
1.7.7+, 1.8 before 1.8.9, and 1.9 before 1.9.5 allows user-assisted
attackers to read arbitrary files via an input command in a '$$'
sequence, which causes LaTeX to include the contents of the file.
Upstream bug and CVS commit:
http://tracker.moodle.org/browse/MDL-18552
http://cvs.moodle.org/moodle/filter/tex/filter.php?r1=1.18.4.4&r2=1.18
.4.5

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://cvs.moodle.org/moodle/filter/tex/filter.php?r1=1.18.4.4&r2=1.18.4.5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0321ab9a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://git.catalyst.net.nz/gw?p="
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://git.catalyst.net.nz/gw?p=moodle-r2.git;a=commitdiff;h=cc9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tracker.moodle.org/browse/MDL-18552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/archive/1/502231/100/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/bid/34278"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022025.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6913af45"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected moodle package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/03");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"moodle-1.9.4-6.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "moodle");
}
