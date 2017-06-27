#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60808);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2008-5913", "CVE-2010-0182", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1202", "CVE-2010-1203");

  script_name(english:"Scientific Linux Security Update : firefox on SL5.x i386/x86_64");
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
running Firefox. (CVE-2010-1121, CVE-2010-1200, CVE-2010-1202,
CVE-2010-1203)

A flaw was found in the way browser plug-ins interact. It was possible
for a plug-in to reference the freed memory from a different plug-in,
resulting in the execution of arbitrary code with the privileges of
the user running Firefox. (CVE-2010-1198)

Several integer overflow flaws were found in the processing of
malformed web content. A web page containing malicious content could
cause Firefox to crash or, potentially, execute arbitrary code with
the privileges of the user running Firefox. (CVE-2010-1196,
CVE-2010-1199)

A focus stealing flaw was found in the way Firefox handled focus
changes. A malicious website could use this flaw to steal sensitive
data from a user, such as usernames and passwords. (CVE-2010-1125)

A flaw was found in the way Firefox handled the 'Content-Disposition:
attachment' HTTP header when the 'Content-Type: multipart' HTTP header
was also present. A website that allows arbitrary uploads and relies
on the 'Content-Disposition: attachment' HTTP header to prevent
content from being displayed inline, could be used by an attacker to
serve malicious content to users. (CVE-2010-1197)

A flaw was found in the Firefox Math.random() function. This function
could be used to identify a browsing session and track a user across
different websites. (CVE-2008-5913)

A flaw was found in the Firefox XML document loading security checks.
Certain security checks were not being called when an XML document was
loaded. This could possibly be leveraged later by an attacker to load
certain resources that violate the security policies of the browser or
its add-ons. Note that this issue cannot be exploited by only loading
an XML document. (CVE-2010-0182)

This erratum upgrades Firefox from version 3.0.19 to version 3.6.4.
Due to the requirements of Firefox 3.6.4, this erratum also provides a
number of other updated packages, including esc, totem, and yelp.

This erratum also contains multiple bug fixes and numerous
enhancements. Space precludes documenting these changes in this
advisory.

Important: Firefox 3.6.4 is not completely backwards-compatible with
all Mozilla Add-ons and Firefox plug-ins that worked with Firefox
3.0.19. Firefox 3.6 checks compatibility on first-launch, and,
depending on the individual configuration and the installed Add-ons
and plug-ins, may disable said Add-ons and plug-ins, or attempt to
check for updates and upgrade them. Add-ons and plug-ins may have to
be manually updated.

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1006&L=scientific-linux-errata&T=0&P=1511
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7b0d130"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/22");
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
if (rpm_check(release:"SL5", reference:"devhelp-0.12-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"devhelp-devel-0.12-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"esc-1.1.0-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"firefox-3.6.4-8.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gnome-python2-extras-2.14.2-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gnome-python2-gtkhtml2-2.14.2-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gnome-python2-gtkmozembed-2.14.2-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gnome-python2-gtkspell-2.14.2-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"gnome-python2-libegg-2.14.2-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"totem-2.16.7-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"totem-devel-2.16.7-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"totem-mozplugin-2.16.7-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.2.4-9.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.2.4-9.el5")) flag++;
if (rpm_check(release:"SL5", reference:"yelp-2.16.0-26.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
