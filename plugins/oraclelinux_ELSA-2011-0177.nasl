#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0177 and 
# Oracle Linux Security Advisory ELSA-2011-0177 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68187);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/06 16:53:48 $");

  script_cve_id("CVE-2010-1780", "CVE-2010-1782", "CVE-2010-1783", "CVE-2010-1784", "CVE-2010-1785", "CVE-2010-1786", "CVE-2010-1787", "CVE-2010-1788", "CVE-2010-1790", "CVE-2010-1792", "CVE-2010-1793", "CVE-2010-1807", "CVE-2010-1812", "CVE-2010-1814", "CVE-2010-1815", "CVE-2010-3113", "CVE-2010-3114", "CVE-2010-3115", "CVE-2010-3116", "CVE-2010-3119", "CVE-2010-3255", "CVE-2010-3257", "CVE-2010-3259", "CVE-2010-3812", "CVE-2010-3813", "CVE-2010-4197", "CVE-2010-4198", "CVE-2010-4204", "CVE-2010-4206", "CVE-2010-4577");
  script_bugtraq_id(42034, 42035, 42036, 42037, 42038, 42041, 42042, 42043, 42044, 42046, 42049, 43047, 43079, 43081, 43083, 44199, 44200, 44201, 44203, 44204, 44206, 44954, 44960, 45718, 45719, 45720, 45721, 45722);
  script_osvdb_id(66846, 66847, 66850, 66857, 67460, 67461, 67863, 69164, 70105, 89663);
  script_xref(name:"RHSA", value:"2011:0177");

  script_name(english:"Oracle Linux 6 : webkitgtk (ELSA-2011-0177)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0177 :

Updated webkitgtk packages that fix several security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

WebKitGTK+ is the port of the portable web rendering engine WebKit to
the GTK+ platform.

Multiple memory corruption flaws were found in WebKit. Malicious web
content could cause an application using WebKitGTK+ to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2010-1782, CVE-2010-1783, CVE-2010-1784,
CVE-2010-1785, CVE-2010-1787, CVE-2010-1788, CVE-2010-1790,
CVE-2010-1792, CVE-2010-1807, CVE-2010-1814, CVE-2010-3114,
CVE-2010-3116, CVE-2010-3119, CVE-2010-3255, CVE-2010-3812,
CVE-2010-4198)

Multiple use-after-free flaws were found in WebKit. Malicious web
content could cause an application using WebKitGTK+ to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2010-1780, CVE-2010-1786, CVE-2010-1793,
CVE-2010-1812, CVE-2010-1815, CVE-2010-3113, CVE-2010-3257,
CVE-2010-4197, CVE-2010-4204)

Two array index errors, leading to out-of-bounds memory reads, were
found in WebKit. Malicious web content could cause an application
using WebKitGTK+ to crash. (CVE-2010-4206, CVE-2010-4577)

A flaw in WebKit could allow malicious web content to trick a user
into thinking they are visiting the site reported by the location bar,
when the page is actually content controlled by an attacker.
(CVE-2010-3115)

It was found that WebKit did not correctly restrict read access to
images created from the 'canvas' element. Malicious web content could
allow a remote attacker to bypass the same-origin policy and
potentially access sensitive image data. (CVE-2010-3259)

A flaw was found in the way WebKit handled DNS prefetching. Even when
it was disabled, web content containing certain 'link' elements could
cause WebKitGTK+ to perform DNS prefetching. (CVE-2010-3813)

Users of WebKitGTK+ should upgrade to these updated packages, which
contain WebKitGTK+ version 1.2.6, and resolve these issues. All
running applications that use WebKitGTK+ must be restarted for this
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001875.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkitgtk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:webkitgtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:webkitgtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:webkitgtk-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
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
if (rpm_check(release:"EL6", reference:"webkitgtk-1.2.6-2.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"webkitgtk-devel-1.2.6-2.el6_0")) flag++;
if (rpm_check(release:"EL6", reference:"webkitgtk-doc-1.2.6-2.el6_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkitgtk / webkitgtk-devel / webkitgtk-doc");
}
