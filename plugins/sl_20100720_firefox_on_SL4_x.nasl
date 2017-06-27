#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60818);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-0654", "CVE-2010-1205", "CVE-2010-1206", "CVE-2010-1207", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1210", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213", "CVE-2010-1214", "CVE-2010-1215", "CVE-2010-2751", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754");

  script_name(english:"Scientific Linux Security Update : firefox on SL4.x, SL5.x i386/x86_64");
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
"Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2010-1208, CVE-2010-1209, CVE-2010-1211,
CVE-2010-1212, CVE-2010-1214, CVE-2010-1215, CVE-2010-2752,
CVE-2010-2753)

A memory corruption flaw was found in the way Firefox decoded certain
PNG images. An attacker could create a specially crafted PNG image
that, when opened, could cause Firefox to crash or, potentially,
execute arbitrary code with the privileges of the user running
Firefox. (CVE-2010-1205)

Several same-origin policy bypass flaws were found in Firefox. An
attacker could create a malicious web page that, when viewed by a
victim, could steal private data from a different website the victim
has loaded with Firefox. (CVE-2010-0654, CVE-2010-1207, CVE-2010-1213,
CVE-2010-2754)

A flaw was found in the way Firefox presented the location bar to a
user. A malicious website could trick a user into thinking they are
visiting the site reported by the location bar, when the page is
actually content controlled by an attacker. (CVE-2010-1206)

A flaw was found in the way Firefox displayed the location bar when
visiting a secure web page. A malicious server could use this flaw to
present data that appears to originate from a secure server, even
though it does not. (CVE-2010-2751)

A flaw was found in the way Firefox displayed certain malformed
characters. A malicious web page could use this flaw to bypass certain
string sanitization methods, allowing it to display malicious
information to users. (CVE-2010-1210)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.7.

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1007&L=scientific-linux-errata&T=0&P=2622
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2d3a0a5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected firefox, xulrunner and / or xulrunner-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"firefox-3.6.7-2.el4")) flag++;

if (rpm_check(release:"SL5", reference:"firefox-3.6.7-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.2.7-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.2.7-2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
