#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61143);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2998", "CVE-2011-2999", "CVE-2011-3000");

  script_name(english:"Scientific Linux Security Update : firefox on SL4.x, SL5.x, SL6.x i386/x86_64");
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
running Firefox. (CVE-2011-2995)

A flaw was found in the way Firefox processed the 'Enter' keypress
event. A malicious web page could present a download dialog while the
key is pressed, activating the default 'Open' action. A remote
attacker could exploit this vulnerability by causing the browser to
open malicious web content. (CVE-2011-2372)

A flaw was found in the way Firefox handled Location headers in
redirect responses. Two copies of this header with different values
could be a symptom of a CRLF injection attack against a vulnerable
server. Firefox now treats two copies of the Location, Content-Length,
or Content-Disposition header as an error condition. (CVE-2011-3000)

A flaw was found in the way Firefox handled frame objects with certain
names. An attacker could use this flaw to cause a plug-in to grant its
content access to another site or the local file system, violating the
same-origin policy. (CVE-2011-2999)

An integer underflow flaw was found in the way Firefox handled large
JavaScript regular expressions. A web page containing malicious
JavaScript could cause Firefox to access already freed memory, causing
Firefox to crash or, potentially, execute arbitrary code with the
privileges of the user running Firefox. (CVE-2011-2998)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.23. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.23, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1109&L=scientific-linux-errata&T=0&P=4108
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5375c0a3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/28");
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
if (rpm_check(release:"SL4", reference:"firefox-3.6.23-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"firefox-debuginfo-3.6.23-1.el4")) flag++;

if (rpm_check(release:"SL5", reference:"firefox-3.6.23-2.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"firefox-debuginfo-3.6.23-2.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.2.23-1.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-debuginfo-1.9.2.23-1.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.2.23-1.el5_7")) flag++;

if (rpm_check(release:"SL6", reference:"firefox-3.6.23-2.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"firefox-debuginfo-3.6.23-2.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-1.9.2.23-1.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-debuginfo-1.9.2.23-1.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-devel-1.9.2.23-1.el6_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
