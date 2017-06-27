#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63019);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/02/23 03:34:18 $");

  script_cve_id("CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4207", "CVE-2012-4209", "CVE-2012-4210", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5839", "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842");

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
"Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2012-4214, CVE-2012-4215, CVE-2012-4216,
CVE-2012-5829, CVE-2012-5830, CVE-2012-5833, CVE-2012-5835,
CVE-2012-5839, CVE-2012-5840, CVE-2012-5842)

A buffer overflow flaw was found in the way Firefox handled GIF
(Graphics Interchange Format) images. A web page containing a
malicious GIF image could cause Firefox to crash or, possibly, execute
arbitrary code with the privileges of the user running Firefox.
(CVE-2012-4202)

A flaw was found in the way the Style Inspector tool in Firefox
handled certain Cascading Style Sheets (CSS). Running the tool (Tools
-> Web Developer -> Inspect) on malicious CSS could result in the
execution of HTML and CSS content with chrome privileges.
(CVE-2012-4210)

A flaw was found in the way Firefox decoded the HZ-GB-2312 character
encoding. A web page containing malicious content could cause Firefox
to run JavaScript code with the permissions of a different website.
(CVE-2012-4207)

A flaw was found in the location object implementation in Firefox.
Malicious content could possibly use this flaw to allow restricted
content to be loaded by plug-ins. (CVE-2012-4209)

A flaw was found in the way cross-origin wrappers were implemented.
Malicious content could use this flaw to perform cross-site scripting
attacks. (CVE-2012-5841)

A flaw was found in the evalInSandbox implementation in Firefox.
Malicious content could use this flaw to perform cross-site scripting
attacks. (CVE-2012-4201)

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1211&L=scientific-linux-errata&T=0&P=1816
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc9c2af9"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"firefox-10.0.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-10.0.11-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-10.0.11-1.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"firefox-10.0.11-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-10.0.11-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-devel-10.0.11-1.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
