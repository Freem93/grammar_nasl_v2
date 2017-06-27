#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60943);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/29 15:23:52 $");

  script_cve_id("CVE-2010-1780", "CVE-2010-1782", "CVE-2010-1783", "CVE-2010-1784", "CVE-2010-1785", "CVE-2010-1786", "CVE-2010-1787", "CVE-2010-1788", "CVE-2010-1790", "CVE-2010-1792", "CVE-2010-1793", "CVE-2010-1807", "CVE-2010-1812", "CVE-2010-1814", "CVE-2010-1815", "CVE-2010-3113", "CVE-2010-3114", "CVE-2010-3115", "CVE-2010-3116", "CVE-2010-3119", "CVE-2010-3255", "CVE-2010-3257", "CVE-2010-3259", "CVE-2010-3812", "CVE-2010-3813", "CVE-2010-4197", "CVE-2010-4198", "CVE-2010-4204", "CVE-2010-4206", "CVE-2010-4577");

  script_name(english:"Scientific Linux Security Update : webkitgtk on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple memory corruption flaws were found in WebKit. Malicious web
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

All running applications that use WebKitGTK+ must be restarted for
this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=4916
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14105c2b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected webkitgtk, webkitgtk-devel and / or webkitgtk-doc
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"webkitgtk-1.2.6-2.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"webkitgtk-devel-1.2.6-2.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"webkitgtk-doc-1.2.6-2.el6_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
