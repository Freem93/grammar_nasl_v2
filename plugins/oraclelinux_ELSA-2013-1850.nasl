#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1850 and 
# Oracle Linux Security Advisory ELSA-2013-1850 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71513);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/09/30 13:55:33 $");

  script_cve_id("CVE-2013-1447", "CVE-2013-6045", "CVE-2013-6052", "CVE-2013-6054");
  script_bugtraq_id(64109, 64113, 64118, 64142);
  script_osvdb_id(100628, 100629, 100630, 100631, 100632, 100633, 100634, 100635, 100636, 100637, 100638, 100639, 100640, 100641, 100642, 100644, 100645, 100646);
  script_xref(name:"RHSA", value:"2013:1850");

  script_name(english:"Oracle Linux 6 : openjpeg (ELSA-2013-1850)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:1850 :

Updated openjpeg packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenJPEG is an open source library for reading and writing image files
in JPEG 2000 format.

Multiple heap-based buffer overflow flaws were found in OpenJPEG. An
attacker could create a specially crafted OpenJPEG image that, when
opened, could cause an application using openjpeg to crash or,
possibly, execute arbitrary code with the privileges of the user
running the application. (CVE-2013-6045, CVE-2013-6054)

Multiple denial of service flaws were found in OpenJPEG. An attacker
could create a specially crafted OpenJPEG image that, when opened,
could cause an application using openjpeg to crash (CVE-2013-1447,
CVE-2013-6052)

Red Hat would like to thank Raphael Geissert for reporting these
issues.

Users of OpenJPEG are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All running
applications using OpenJPEG must be restarted for the update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-December/003883.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openjpeg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openjpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openjpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openjpeg-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"openjpeg-1.3-10.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"openjpeg-devel-1.3-10.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"openjpeg-libs-1.3-10.el6_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjpeg / openjpeg-devel / openjpeg-libs");
}
