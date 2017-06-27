#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61322);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2011-3101", "CVE-2012-1940", "CVE-2012-1944", "CVE-2012-1945", "CVE-2012-1946");

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

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2011-3101, CVE-2012-1937, CVE-2012-1938,
CVE-2012-1939, CVE-2012-1940, CVE-2012-1941, CVE-2012-1946,
CVE-2012-1947)

Note: CVE-2011-3101 only affected users of certain NVIDIA display
drivers with graphics cards that have hardware acceleration enabled.

It was found that the Content Security Policy (CSP) implementation in
Firefox no longer blocked Firefox inline event handlers. A remote
attacker could use this flaw to possibly bypass a web application's
intended restrictions, if that application relied on CSP to protect
against flaws such as cross-site scripting (XSS). (CVE-2012-1944)

If a web server hosted HTML files that are stored on a Microsoft
Windows share, or a Samba share, loading such files with Firefox could
result in Windows shortcut files (.lnk) in the same share also being
loaded. An attacker could use this flaw to view the contents of local
files and directories on the victim's system. This issue also affected
users opening HTML files from Microsoft Windows shares, or Samba
shares, that are mounted on their systems. (CVE-2012-1945)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 10.0.5 ESR.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 10.0.5 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1206&L=scientific-linux-errata&T=0&P=579
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?515aa73f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
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
if (rpm_check(release:"SL5", reference:"firefox-10.0.5-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"firefox-debuginfo-10.0.5-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-10.0.5-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-debuginfo-10.0.5-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-10.0.5-1.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"firefox-10.0.5-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"firefox-debuginfo-10.0.5-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-10.0.5-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-debuginfo-10.0.5-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-devel-10.0.5-1.el6_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
