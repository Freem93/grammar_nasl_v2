#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60506);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5505", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513");

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
potentially, execute arbitrary code as the user running Firefox.
(CVE-2008-5500, CVE-2008-5501, CVE-2008-5502, CVE-2008-5511,
CVE-2008-5512, CVE-2008-5513)

Several flaws were found in the way malformed content was processed. A
website containing specially crafted content could potentially trick a
Firefox user into surrendering sensitive information. (CVE-2008-5506,
CVE-2008-5507)

A flaw was found in the way Firefox stored attributes in XML User
Interface Language (XUL) elements. A website could use this flaw to
track users across browser sessions, even if users did not allow the
site to store cookies in the victim's browser. (CVE-2008-5505)

A flaw was found in the way malformed URLs were processed by Firefox.
This flaw could prevent various URL sanitization mechanisms from
properly parsing a malicious URL. (CVE-2008-5508)

A flaw was found in Firefox's CSS parser. A malicious web page could
inject NULL characters into a CSS input string, possibly bypassing an
application's script sanitization routines. (CVE-2008-5510)

For technical details regarding these flaws, please see the Mozilla
security advisories for Firefox 3.0.5. You can find a link to the
Mozilla advisories in the References section.

Note: after the errata packages are installed, Firefox must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0812&L=scientific-linux-errata&T=0&P=1263
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e60e6515"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"firefox-3.0.5-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nspr-4.7.3-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nspr-devel-4.7.3-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-3.12.2.0-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-devel-3.12.2.0-1.el4")) flag++;

if (rpm_check(release:"SL5", reference:"firefox-3.0.5-1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-4.7.3-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-devel-4.7.3-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-3.12.2.0-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-devel-3.12.2.0-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-pkcs11-devel-3.12.2.0-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-tools-3.12.2.0-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.0.5-1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.0.5-1.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-unstable-1.9.0.5-1.el5_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
