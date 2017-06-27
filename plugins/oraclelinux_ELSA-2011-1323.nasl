#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1323 and 
# Oracle Linux Security Advisory ELSA-2011-1323 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68353);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 17:02:14 $");

  script_cve_id("CVE-2011-3193", "CVE-2011-3194");
  script_bugtraq_id(49724);
  script_osvdb_id(75652);
  script_xref(name:"RHSA", value:"2011:1323");

  script_name(english:"Oracle Linux 6 : qt (ELSA-2011-1323)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1323 :

Updated qt packages that fix two security issues are now available for
Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Qt is a software toolkit that simplifies the task of writing and
maintaining GUI (Graphical User Interface) applications for the X
Window System. HarfBuzz is an OpenType text shaping engine.

A buffer overflow flaw was found in the harfbuzz module in Qt. If a
user loaded a specially crafted font file with an application linked
against Qt, it could cause the application to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2011-3193)

A buffer overflow flaw was found in the way Qt handled certain
gray-scale image files. If a user loaded a specially crafted
gray-scale image file with an application linked against Qt, it could
cause the application to crash or, possibly, execute arbitrary code
with the privileges of the user running the application.
(CVE-2011-3194)

Users of Qt should upgrade to these updated packages, which contain
backported patches to correct these issues. All running applications
linked against Qt libraries must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-September/002367.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:phonon-backend-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
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
if (rpm_check(release:"EL6", reference:"phonon-backend-gstreamer-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"qt-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"qt-demos-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"qt-devel-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"qt-doc-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"qt-examples-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"qt-mysql-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"qt-odbc-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"qt-postgresql-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"qt-sqlite-4.6.2-17.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"qt-x11-4.6.2-17.el6_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phonon-backend-gstreamer / qt / qt-demos / qt-devel / qt-doc / etc");
}
