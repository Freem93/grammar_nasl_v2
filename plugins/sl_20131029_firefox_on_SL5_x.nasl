#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(70704);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/24 03:40:13 $");

  script_cve_id("CVE-2013-5590", "CVE-2013-5595", "CVE-2013-5597", "CVE-2013-5599", "CVE-2013-5600", "CVE-2013-5601", "CVE-2013-5602", "CVE-2013-5604");

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
web page containing malicious content could cause Firefox to terminate
unexpectedly or, potentially, execute arbitrary code with the
privileges of the user running Firefox. (CVE-2013-5590, CVE-2013-5597,
CVE-2013-5599, CVE-2013-5600, CVE-2013-5601, CVE-2013-5602)

It was found that the Firefox JavaScript engine incorrectly allocated
memory for certain functions. An attacker could combine this flaw with
other vulnerabilities to execute arbitrary code with the privileges of
the user running Firefox. (CVE-2013-5595)

A flaw was found in the way Firefox handled certain Extensible
Stylesheet Language Transformations (XSLT) files. An attacker could
combine this flaw with other vulnerabilities to execute arbitrary code
with the privileges of the user running Firefox. (CVE-2013-5604)

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1310&L=scientific-linux-errata&T=0&P=3423
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e0a0423"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"firefox-17.0.10-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"firefox-debuginfo-17.0.10-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-17.0.10-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-debuginfo-17.0.10-1.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-17.0.10-1.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"firefox-17.0.10-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"firefox-debuginfo-17.0.10-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-17.0.10-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-debuginfo-17.0.10-1.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-devel-17.0.10-1.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
