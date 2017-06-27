#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60494);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-0017", "CVE-2008-5014", "CVE-2008-5015", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5019", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024");

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
(CVE-2008-0017, CVE-2008-5014, CVE-2008-5016, CVE-2008-5017,
CVE-2008-5018, CVE-2008-5019, CVE-2008-5021)

Several flaws were found in the way malformed content was processed. A
web site containing specially crafted content could potentially trick
a Firefox user into surrendering sensitive information.
(CVE-2008-5022, CVE-2008-5023, CVE-2008-5024)

A flaw was found in the way Firefox opened 'file:' URIs. If a file:
URI was loaded in the same tab as a chrome or privileged 'about:'
page, the file: URI could execute arbitrary code with the permissions
of the user running Firefox. (CVE-2008-5015)

For technical details regarding these flaws, please see the Mozilla
security advisories for Firefox 3.0.4."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0811&L=scientific-linux-errata&T=0&P=1183
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a6470a6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 94, 119, 189, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/12");
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
if (rpm_check(release:"SL4", reference:"firefox-3.0.4-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-3.12.1.1-3.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-devel-3.12.1.1-3.el4")) flag++;

if (rpm_check(release:"SL5", reference:"devhelp-0.12-20.el5")) flag++;
if (rpm_check(release:"SL5", reference:"devhelp-devel-0.12-20.el5")) flag++;
if (rpm_check(release:"SL5", reference:"firefox-3.0.4-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-3.12.1.1-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-devel-3.12.1.1-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-pkcs11-devel-3.12.1.1-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"nss-tools-3.12.1.1-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.0.4-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.0.4-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-unstable-1.9.0.4-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"yelp-2.16.0-22.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
