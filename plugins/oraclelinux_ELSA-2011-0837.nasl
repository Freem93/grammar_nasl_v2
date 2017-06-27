#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0837 and 
# Oracle Linux Security Advisory ELSA-2011-0837 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68278);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:57:59 $");

  script_cve_id("CVE-2009-1570", "CVE-2010-4541", "CVE-2010-4543", "CVE-2011-1178");
  script_bugtraq_id(37006, 45647);
  script_osvdb_id(70281, 70284);
  script_xref(name:"RHSA", value:"2011:0837");

  script_name(english:"Oracle Linux 4 : gimp (ELSA-2011-0837)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0837 :

Updated gimp packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The GIMP (GNU Image Manipulation Program) is an image composition and
editing program.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the GIMP's Microsoft Windows Bitmap (BMP) and Personal
Computer eXchange (PCX) image file plug-ins. An attacker could create
a specially crafted BMP or PCX image file that, when opened, could
cause the relevant plug-in to crash or, potentially, execute arbitrary
code with the privileges of the user running the GIMP. (CVE-2009-1570,
CVE-2011-1178)

A heap-based buffer overflow flaw was found in the GIMP's Paint Shop
Pro (PSP) image file plug-in. An attacker could create a specially
crafted PSP image file that, when opened, could cause the PSP plug-in
to crash or, potentially, execute arbitrary code with the privileges
of the user running the GIMP. (CVE-2010-4543)

A stack-based buffer overflow flaw was found in the GIMP's Sphere
Designer image filter. An attacker could create a specially crafted
Sphere Designer filter configuration file that, when opened, could
cause the Sphere Designer plug-in to crash or, potentially, execute
arbitrary code with the privileges of the user running the GIMP.
(CVE-2010-4541)

Red Hat would like to thank Stefan Cornelius of Secunia Research for
responsibly reporting the CVE-2009-1570 flaw.

Users of the GIMP are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The GIMP
must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-May/002151.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/31");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"gimp-2.0.5-7.0.7.el4.1")) flag++;
if (rpm_check(release:"EL4", reference:"gimp-devel-2.0.5-7.0.7.el4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-devel");
}
