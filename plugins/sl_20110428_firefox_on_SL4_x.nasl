#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61025);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081", "CVE-2011-1202");

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
web page containing malicious content could possibly lead to arbitrary
code execution with the privileges of the user running Firefox.
(CVE-2011-0080, CVE-2011-0081)

An arbitrary memory write flaw was found in the way Firefox handled
out-of-memory conditions. If all memory was consumed when a user
visited a malicious web page, it could possibly lead to arbitrary code
execution with the privileges of the user running Firefox.
(CVE-2011-0078)

An integer overflow flaw was found in the way Firefox handled the HTML
frameset tag. A web page with a frameset tag containing large values
for the 'rows' and 'cols' attributes could trigger this flaw, possibly
leading to arbitrary code execution with the privileges of the user
running Firefox. (CVE-2011-0077)

A flaw was found in the way Firefox handled the HTML iframe tag. A web
page with an iframe tag containing a specially crafted source address
could trigger this flaw, possibly leading to arbitrary code execution
with the privileges of the user running Firefox. (CVE-2011-0075)

A flaw was found in the way Firefox displayed multiple marquee
elements. A malformed HTML document could cause Firefox to execute
arbitrary code with the privileges of the user running Firefox.
(CVE-2011-0074)

A flaw was found in the way Firefox handled the nsTreeSelection
element. Malformed content could cause Firefox to execute arbitrary
code with the privileges of the user running Firefox. (CVE-2011-0073)

A use-after-free flaw was found in the way Firefox appended frame and
iframe elements to a DOM tree when the NoScript add-on was enabled.
Malicious HTML content could cause Firefox to execute arbitrary code
with the privileges of the user running Firefox. (CVE-2011-0072)

A directory traversal flaw was found in the Firefox resource://
protocol handler. Malicious content could cause Firefox to access
arbitrary files accessible to the user running Firefox.
(CVE-2011-0071)

A double free flaw was found in the way Firefox handled
'application/http-index-format' documents. A malformed HTTP response
could cause Firefox to execute arbitrary code with the privileges of
the user running Firefox. (CVE-2011-0070)

A flaw was found in the way Firefox handled certain JavaScript
cross-domain requests. If malicious content generated a large number
of cross-domain JavaScript requests, it could cause Firefox to execute
arbitrary code with the privileges of the user running Firefox.
(CVE-2011-0069)

A flaw was found in the way Firefox displayed the autocomplete pop-up.
Malicious content could use this flaw to steal form history
information. (CVE-2011-0067)

Two use-after-free flaws were found in the Firefox mObserverList and
mChannel objects. Malicious content could use these flaws to execute
arbitrary code with the privileges of the user running Firefox.
(CVE-2011-0066, CVE-2011-0065)

A flaw was found in the Firefox XSLT generate-id() function. This
function returned the memory address of an object in memory, which
could possibly be used by attackers to bypass address randomization
protections. (CVE-2011-1202)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.17. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.17, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1104&L=scientific-linux-errata&T=0&P=3138
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0dcc83f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected firefox, xulrunner and / or xulrunner-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox "nsTreeRange" Dangling Pointer Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/28");
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
if (rpm_check(release:"SL4", reference:"firefox-3.6.17-2.el4")) flag++;

if (rpm_check(release:"SL5", reference:"firefox-3.6.17-1.el5_6")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.2.17-3.el5_6")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.2.17-3.el5_6")) flag++;

if (rpm_check(release:"SL6", reference:"firefox-3.6.17-1.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-1.9.2.17-4.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-devel-1.9.2.17-4.el6_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
