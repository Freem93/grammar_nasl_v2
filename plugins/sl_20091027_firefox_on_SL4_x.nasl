#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60683);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-0689", "CVE-2009-3274", "CVE-2009-3370", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3380", "CVE-2009-3382");

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
"A flaw was found in the way Firefox handles form history. A malicious
web page could steal saved form data by synthesizing input events,
causing the browser to auto-fill form fields (which could then be read
by an attacker). (CVE-2009-3370)

A flaw was found in the way Firefox creates temporary file names for
downloaded files. If a local attacker knows the name of a file Firefox
is going to download, they can replace the contents of that file with
arbitrary contents. (CVE-2009-3274)

A flaw was found in the Firefox Proxy Auto-Configuration (PAC) file
processor. If Firefox loads a malicious PAC file, it could crash
Firefox or, potentially, execute arbitrary code with the privileges of
the user running Firefox. (CVE-2009-3372)

A heap-based buffer overflow flaw was found in the Firefox GIF image
processor. A malicious GIF image could crash Firefox or, potentially,
execute arbitrary code with the privileges of the user running
Firefox. (CVE-2009-3373)

A heap-based buffer overflow flaw was found in the Firefox string to
floating point conversion routines. A web page containing malicious
JavaScript could crash Firefox or, potentially, execute arbitrary code
with the privileges of the user running Firefox. (CVE-2009-1563)

A flaw was found in the way Firefox handles text selection. A
malicious website may be able to read highlighted text in a different
domain (e.g. another website the user is viewing), bypassing the
same-origin policy. (CVE-2009-3375)

A flaw was found in the way Firefox displays a right-to-left override
character when downloading a file. In these cases, the name displayed
in the title bar differs from the name displayed in the dialog body.
An attacker could use this flaw to trick a user into downloading a
file that has a file name or extension that differs from what the user
expected. (CVE-2009-3376)

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2009-3374, CVE-2009-3380, CVE-2009-3382)

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0910&L=scientific-linux-errata&T=0&P=2204
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fe32619"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/27");
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
if (rpm_check(release:"SL4", reference:"firefox-3.0.15-3.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nspr-4.7.6-1.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"nspr-devel-4.7.6-1.el4_8")) flag++;

if (rpm_check(release:"SL5", reference:"firefox-3.0.15-3.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-4.7.6-1.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-devel-4.7.6-1.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.0.15-3.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.0.15-3.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-unstable-1.9.0.15-3.el5_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
