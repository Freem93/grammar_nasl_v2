#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0696 and 
# Oracle Linux Security Advisory ELSA-2015-0696 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81902);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id("CVE-2014-9657", "CVE-2014-9658", "CVE-2014-9660", "CVE-2014-9661", "CVE-2014-9663", "CVE-2014-9664", "CVE-2014-9667", "CVE-2014-9669", "CVE-2014-9670", "CVE-2014-9671", "CVE-2014-9673", "CVE-2014-9674", "CVE-2014-9675");
  script_osvdb_id(114332, 114333, 114354, 114619, 114621, 114961, 114962, 114964, 114965, 115073, 115075, 115098);
  script_xref(name:"RHSA", value:"2015:0696");

  script_name(english:"Oracle Linux 6 / 7 : freetype (ELSA-2015-0696)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0696 :

Updated freetype packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

FreeType is a free, high-quality, portable font engine that can open
and manage font files. It also loads, hints, and renders individual
glyphs efficiently.

Multiple integer overflow flaws and an integer signedness flaw,
leading to heap-based buffer overflows, were found in the way FreeType
handled Mac fonts. If a specially crafted font file was loaded by an
application linked against FreeType, it could cause the application to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2014-9673, CVE-2014-9674)

Multiple flaws were found in the way FreeType handled fonts in various
formats. If a specially crafted font file was loaded by an application
linked against FreeType, it could cause the application to crash or,
possibly, disclose a portion of the application memory.
(CVE-2014-9657, CVE-2014-9658, CVE-2014-9660, CVE-2014-9661,
CVE-2014-9663, CVE-2014-9664, CVE-2014-9667, CVE-2014-9669,
CVE-2014-9670, CVE-2014-9671, CVE-2014-9675)

All freetype users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The X server
must be restarted (log out, then log back in) for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004909.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004910.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"freetype-2.3.11-15.el6_6.1")) flag++;
if (rpm_check(release:"EL6", reference:"freetype-demos-2.3.11-15.el6_6.1")) flag++;
if (rpm_check(release:"EL6", reference:"freetype-devel-2.3.11-15.el6_6.1")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"freetype-2.4.11-10.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"freetype-demos-2.4.11-10.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"freetype-devel-2.4.11-10.el7_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype / freetype-demos / freetype-devel");
}
