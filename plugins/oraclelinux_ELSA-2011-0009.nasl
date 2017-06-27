#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0009 and 
# Oracle Linux Security Advisory ELSA-2011-0009 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68178);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:57:58 $");

  script_cve_id("CVE-2010-2640", "CVE-2010-2641", "CVE-2010-2642", "CVE-2010-2643");
  script_bugtraq_id(45678);
  script_osvdb_id(70300, 70301, 70302, 70303);
  script_xref(name:"RHSA", value:"2011:0009");

  script_name(english:"Oracle Linux 6 : evince (ELSA-2011-0009)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0009 :

Updated evince packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Evince is a document viewer.

An array index error was found in the DeVice Independent (DVI)
renderer's PK and VF font file parsers. A DVI file that references a
specially crafted font file could, when opened, cause Evince to crash
or, potentially, execute arbitrary code with the privileges of the
user running Evince. (CVE-2010-2640, CVE-2010-2641)

A heap-based buffer overflow flaw was found in the DVI renderer's AFM
font file parser. A DVI file that references a specially crafted font
file could, when opened, cause Evince to crash or, potentially,
execute arbitrary code with the privileges of the user running Evince.
(CVE-2010-2642)

An integer overflow flaw was found in the DVI renderer's TFM font file
parser. A DVI file that references a specially crafted font file
could, when opened, cause Evince to crash or, potentially, execute
arbitrary code with the privileges of the user running Evince.
(CVE-2010-2643)

Note: The above issues are not exploitable unless an attacker can
trick the user into installing a malicious font file.

Red Hat would like to thank the Evince development team for reporting
these issues. Upstream acknowledges Jon Larimer of IBM X-Force as the
original reporter of these issues.

Users are advised to upgrade to these updated packages, which contain
a backported patch to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001857.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evince packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-dvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evince-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
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
if (rpm_check(release:"EL6", reference:"evince-2.28.2-14.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"evince-devel-2.28.2-14.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"evince-dvi-2.28.2-14.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"evince-libs-2.28.2-14.el6_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evince / evince-devel / evince-dvi / evince-libs");
}
