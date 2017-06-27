#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60916);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2010-0179", "CVE-2010-3766", "CVE-2010-3767", "CVE-2010-3768", "CVE-2010-3770", "CVE-2010-3771", "CVE-2010-3772", "CVE-2010-3773", "CVE-2010-3774", "CVE-2010-3775", "CVE-2010-3776", "CVE-2010-3777");

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
running Firefox. (CVE-2010-3766, CVE-2010-3767, CVE-2010-3772,
CVE-2010-3776, CVE-2010-3777)

A flaw was found in the way Firefox handled malformed JavaScript. A
website with an object containing malicious JavaScript could cause
Firefox to execute that JavaScript with the privileges of the user
running Firefox. (CVE-2010-3771)

This update adds support for the Sanitiser for OpenType (OTS) library
to Firefox. This library helps prevent potential exploits in malformed
OpenType fonts by verifying the font file prior to use.
(CVE-2010-3768)

A flaw was found in the way Firefox loaded Java LiveConnect scripts.
Malicious web content could load a Java LiveConnect script in a way
that would result in the plug-in object having elevated privileges,
allowing it to execute Java code with the privileges of the user
running Firefox. (CVE-2010-3775)

It was found that the fix for CVE-2010-0179 was incomplete when the
Firebug add-on was used. If a user visited a website containing
malicious JavaScript while the Firebug add-on was enabled, it could
cause Firefox to execute arbitrary JavaScript with the privileges of
the user running Firefox. (CVE-2010-3773)

A flaw was found in the way Firefox presented the location bar to
users. A malicious website could trick a user into thinking they are
visiting the site reported by the location bar, when the page is
actually content controlled by an attacker. (CVE-2010-3774)

A cross-site scripting (XSS) flaw was found in the Firefox
x-mac-arabic, x-mac-farsi, and x-mac-hebrew character encodings.
Certain characters were converted to angle brackets when displayed. If
server-side script filtering missed these cases, it could result in
Firefox executing JavaScript code with the permissions of a different
website. (CVE-2010-3770)

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1012&L=scientific-linux-errata&T=0&P=926
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a561cb11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected firefox, xulrunner and / or xulrunner-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/09");
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
if (rpm_check(release:"SL4", reference:"firefox-3.6.13-3.el4")) flag++;

if (rpm_check(release:"SL5", reference:"firefox-3.6.13-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.2.13-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.2.13-3.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
