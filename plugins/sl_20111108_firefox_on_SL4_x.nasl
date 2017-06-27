#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61170);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_cve_id("CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650");

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

A flaw was found in the way Firefox handled certain add-ons. A web
page containing malicious content could cause an add-on to grant
itself full browser privileges, which could lead to arbitrary code
execution with the privileges of the user running Firefox.
(CVE-2011-3647)

A cross-site scripting (XSS) flaw was found in the way Firefox handled
certain multibyte character sets. A web page containing malicious
content could cause Firefox to run JavaScript code with the
permissions of a different website. (CVE-2011-3648)

A flaw was found in the way Firefox handled large JavaScript scripts.
A web page containing malicious JavaScript could cause Firefox to
crash or, potentially, execute arbitrary code with the privileges of
the user running Firefox. (CVE-2011-3650)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.6.24. You can find a link to the
Mozilla advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.6.24, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1111&L=scientific-linux-errata&T=0&P=1084
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1651dd6c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
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
if (rpm_check(release:"SL4", reference:"firefox-3.6.24-3.el4")) flag++;
if (rpm_check(release:"SL4", reference:"firefox-debuginfo-3.6.24-3.el4")) flag++;

if (rpm_check(release:"SL5", reference:"firefox-3.6.24-3.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"firefox-debuginfo-3.6.24-3.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.2.24-2.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-debuginfo-1.9.2.24-2.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.2.24-2.el5_7")) flag++;

if (rpm_check(release:"SL6", reference:"firefox-3.6.24-3.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"firefox-debuginfo-3.6.24-3.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-1.9.2.24-2.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-debuginfo-1.9.2.24-2.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-devel-1.9.2.24-2.el6_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
