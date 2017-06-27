#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61726);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/10/27 02:34:23 $");

  script_cve_id("CVE-2012-1970", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3966", "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3972", "CVE-2012-3976", "CVE-2012-3978", "CVE-2012-3980");

  script_name(english:"Scientific Linux Security Update : firefox on SL5.x, SL6.x i386/x86_64");
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
"Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

A web page containing malicious content could cause Firefox to crash
or, potentially, execute arbitrary code with the privileges of the
user running Firefox. (CVE-2012-1970, CVE-2012-1972, CVE-2012-1973,
CVE-2012-1974, CVE-2012-1975, CVE-2012-1976, CVE-2012-3956,
CVE-2012-3957, CVE-2012-3958, CVE-2012-3959, CVE-2012-3960,
CVE-2012-3961, CVE-2012-3962, CVE-2012-3963, CVE-2012-3964)

A web page containing a malicious Scalable Vector Graphics (SVG) image
file could cause Firefox to crash or, potentially, execute arbitrary
code with the privileges of the user running Firefox. (CVE-2012-3969,
CVE-2012-3970)

Two flaws were found in the way Firefox rendered certain images using
WebGL. A web page containing malicious content could cause Firefox to
crash or, under certain conditions, possibly execute arbitrary code
with the privileges of the user running Firefox. (CVE-2012-3967,
CVE-2012-3968)

A flaw was found in the way Firefox decoded embedded bitmap images in
Icon Format (ICO) files. A web page containing a malicious ICO file
could cause Firefox to crash or, under certain conditions, possibly
execute arbitrary code with the privileges of the user running
Firefox. (CVE-2012-3966)

A flaw was found in the way the 'eval' command was handled by the
Firefox Web Console. Running 'eval' in the Web Console while viewing a
web page containing malicious content could possibly cause Firefox to
execute arbitrary code with the privileges of the user running
Firefox. (CVE-2012-3980)

An out-of-bounds memory read flaw was found in the way Firefox used
the format-number feature of XSLT (Extensible Stylesheet Language
Transformations). A web page containing malicious content could
possibly cause an information leak, or cause Firefox to crash.
(CVE-2012-3972)

It was found that the SSL certificate information for a previously
visited site could be displayed in the address bar while the main
window displayed a new page. This could lead to phishing attacks as
attackers could use this flaw to trick users into believing they are
viewing a trusted site. (CVE-2012-3976)

A flaw was found in the location object implementation in Firefox.
Malicious content could use this flaw to possibly allow restricted
content to be loaded. (CVE-2012-3978)

All Firefox users should upgrade to these updated packages, which
contain Firefox version 10.0.7 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1208&L=scientific-linux-errata&T=0&P=3337
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?459c581c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected firefox, xulrunner and / or xulrunner-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"firefox-10.0.7-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-10.0.7-2.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-10.0.7-2.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"firefox-10.0.7-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-10.0.7-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-devel-10.0.7-1.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
