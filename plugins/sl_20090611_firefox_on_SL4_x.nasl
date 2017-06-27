#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60593);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841");

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
(CVE-2009-1392, CVE-2009-1832, CVE-2009-1833, CVE-2009-1837,
CVE-2009-1838, CVE-2009-1841)

Multiple flaws were found in the processing of malformed, local file
content. If a user loaded malicious, local content via the file://
URL, it was possible for that content to access other local data.
(CVE-2009-1835, CVE-2009-1839)

A script, privilege elevation flaw was found in the way Firefox loaded
XML User Interface Language (XUL) scripts. Firefox and certain add-ons
could load malicious content when certain policy checks did not
happen. (CVE-2009-1840)

A flaw was found in the way Firefox displayed certain Unicode
characters in International Domain Names (IDN). If an IDN contained
invalid characters, they may have been displayed as spaces, making it
appear to the user that they were visiting a trusted site.
(CVE-2009-1834)

A flaw was found in the way Firefox handled error responses returned
from proxy servers. If an attacker is able to conduct a
man-in-the-middle attack against a Firefox instance that is using a
proxy server, they may be able to steal sensitive information from the
site the user is visiting. (CVE-2009-1836)

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0906&L=scientific-linux-errata&T=0&P=305
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50bdeed1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 200, 264, 287, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/11");
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
if (rpm_check(release:"SL4", reference:"firefox-3.0.11-4.el4")) flag++;

if (rpm_check(release:"SL5", reference:"firefox-3.0.11-2.el5_3")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.0.11-3.el5_3")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.0.11-3.el5_3")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-unstable-1.9.0.11-3.el5_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
