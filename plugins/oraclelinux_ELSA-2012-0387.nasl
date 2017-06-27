#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0387 and 
# Oracle Linux Security Advisory ELSA-2012-0387 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68495);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:07:15 $");

  script_cve_id("CVE-2012-0451", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461", "CVE-2012-0462", "CVE-2012-0464");
  script_bugtraq_id(52456, 52457, 52458, 52459, 52460, 52461, 52463, 52464, 52465, 52467);
  script_osvdb_id(80011, 80012, 80013, 80014, 80015, 80016, 80017, 80018, 80019, 80020);
  script_xref(name:"RHSA", value:"2012:0387");

  script_name(english:"Oracle Linux 5 / 6 : firefox (ELSA-2012-0387)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0387 :

Updated firefox packages that fix multiple security issues and three
bugs are now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2012-0461, CVE-2012-0462, CVE-2012-0464)

Two flaws were found in the way Firefox parsed certain Scalable Vector
Graphics (SVG) image files. A web page containing a malicious SVG
image file could cause an information leak, or cause Firefox to crash
or, potentially, execute arbitrary code with the privileges of the
user running Firefox. (CVE-2012-0456, CVE-2012-0457)

A flaw could allow a malicious site to bypass intended restrictions,
possibly leading to a cross-site scripting (XSS) attack if a user were
tricked into dropping a 'javascript:' link onto a frame.
(CVE-2012-0455)

It was found that the home page could be set to a 'javascript:' link.
If a user were tricked into setting such a home page by dragging a
link to the home button, it could cause Firefox to repeatedly crash,
eventually leading to arbitrary code execution with the privileges of
the user running Firefox. (CVE-2012-0458)

A flaw was found in the way Firefox parsed certain web content
containing 'cssText'. A web page containing malicious content could
cause Firefox to crash or, potentially, execute arbitrary code with
the privileges of the user running Firefox. (CVE-2012-0459)

It was found that by using the DOM fullscreen API, untrusted content
could bypass the mozRequestFullscreen security protections. A web page
containing malicious web content could exploit this API flaw to cause
user interface spoofing. (CVE-2012-0460)

A flaw was found in the way Firefox handled pages with multiple
Content Security Policy (CSP) headers. This could lead to a cross-site
scripting attack if used in conjunction with a website that has a
header injection flaw. (CVE-2012-0451)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 10.0.3 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

This update also fixes the following bugs :

* When using the Traditional Chinese locale (zh-TW), a segmentation
fault sometimes occurred when closing Firefox. (BZ#729632)

* Inputting any text in the Web Console (Tools -> Web Developer -> Web
Console) caused Firefox to crash. (BZ#784048)

* The java-1.6.0-ibm-plugin and java-1.6.0-sun-plugin packages require
the '/usr/lib/mozilla/plugins/' directory on 32-bit systems, and the
'/usr/lib64/mozilla/plugins/' directory on 64-bit systems. These
directories are created by the xulrunner package; however, they were
missing from the xulrunner package provided by the RHEA-2012:0327
update. Therefore, upgrading to RHEA-2012:0327 removed those
directories, causing dependency errors when attempting to install the
java-1.6.0-ibm-plugin or java-1.6.0-sun-plugin package. With this
update, xulrunner once again creates the plugins directory. This issue
did not affect users of Red Hat Enterprise Linux 6. (BZ#799042)

All Firefox users should upgrade to these updated packages, which
contain Firefox version 10.0.3 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002699.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002701.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/15");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"firefox-10.0.3-1.0.1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-10.0.3-1.0.1.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"xulrunner-devel-10.0.3-1.0.1.el5_8")) flag++;

if (rpm_check(release:"EL6", reference:"firefox-10.0.3-1.0.1.el6_2")) flag++;
if (rpm_check(release:"EL6", reference:"xulrunner-10.0.3-1.0.1.el6_2")) flag++;
if (rpm_check(release:"EL6", reference:"xulrunner-devel-10.0.3-1.0.1.el6_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / xulrunner / xulrunner-devel");
}
