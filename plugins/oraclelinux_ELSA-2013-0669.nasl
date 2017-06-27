#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0669 and 
# Oracle Linux Security Advisory ELSA-2013-0669 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68795);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:16:04 $");

  script_cve_id("CVE-2013-0254");
  script_bugtraq_id(57772);
  script_osvdb_id(89908);
  script_xref(name:"RHSA", value:"2013:0669");

  script_name(english:"Oracle Linux 6 : qt (ELSA-2013-0669)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0669 :

Updated qt packages that fix one security issue are now available for
Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Qt is a software toolkit that simplifies the task of writing and
maintaining GUI (Graphical User Interface) applications for the X
Window System.

It was discovered that the QSharedMemory class implementation of the
Qt toolkit created shared memory segments with insecure permissions. A
local attacker could use this flaw to read or alter the contents of a
particular shared memory segment, possibly leading to their ability to
obtain sensitive information or influence the behavior of a process
that is using the shared memory segment. (CVE-2013-0254)

Red Hat would like to thank the Qt project for reporting this issue.
Upstream acknowledges Tim Brown and Mark Lowe of Portcullis Computer
Security Ltd. as the original reporters.

Users of Qt should upgrade to these updated packages, which contain a
backported patch to correct this issue. All running applications
linked against Qt libraries must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-March/003378.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qt packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL6", reference:"phonon-backend-gstreamer-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"qt-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"qt-demos-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"qt-devel-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"qt-doc-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"qt-examples-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"qt-mysql-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"qt-odbc-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"qt-postgresql-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"qt-sqlite-4.6.2-26.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"qt-x11-4.6.2-26.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phonon-backend-gstreamer / qt / qt-demos / qt-devel / qt-doc / etc");
}
