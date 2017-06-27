#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60664);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-2654", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");

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
"CVE-2009-2654 firefox: URL bar spoofing vulnerability

CVE-2009-3070 Firefox 3.5 3.0.14 browser engine crashes

CVE-2009-3071 Firefox 3.5.2 3.0.14 browser engine crashes

CVE-2009-3072 Firefox 3.5.3 3.0.14 browser engine crashes

CVE-2009-3074 Firefox 3.5 3.0.14 JavaScript engine crashes

CVE-2009-3075 Firefox 3.5.2 3.0.14 JavaScript engine crashes

CVE-2009-3076 Firefox 3.0.14 Insufficient warning for PKCS11 module
installation and removal

CVE-2009-3077 Firefox 3.5.3 3.0.14 TreeColumns dangling pointer
vulnerability

CVE-2009-3078 Firefox 3.5.3 3.0.14 Location bar spoofing via tall
line-height Unicode characters

CVE-2009-3079 Firefox 3.5.3 3.0.14 Chrome privilege escalation with
FeedWriter

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2009-3070, CVE-2009-3071, CVE-2009-3072,
CVE-2009-3074,

CVE-2009-3075)

A use-after-free flaw was found in Firefox. An attacker could use this
flaw to crash Firefox or, potentially, execute arbitrary code with the
privileges of the user running Firefox. (CVE-2009-3077)

A flaw was found in the way Firefox handles malformed JavaScript. A
website with an object containing malicious JavaScript could execute
that JavaScript with the privileges of the user running Firefox.
(CVE-2009-3079)

Descriptions in the dialogs when adding and removing PKCS #11 modules
were not informative. An attacker able to trick a user into installing
a malicious PKCS #11 module could use this flaw to install their own
Certificate Authority certificates on a user's machine, making it
possible to trick the user into believing they are viewing a trusted
site or, potentially, execute arbitrary code with the privileges of
the user running Firefox. (CVE-2009-3076)

A flaw was found in the way Firefox displays the address bar when
window.open() is called in a certain way. An attacker could use this
flaw to conceal a malicious URL, possibly tricking a user into
believing they are viewing a trusted site. (CVE-2009-2654)

A flaw was found in the way Firefox displays certain Unicode
characters. An attacker could use this flaw to conceal a malicious
URL, possibly tricking a user into believing they are viewing a
trusted site. (CVE-2009-3078)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.0.14. You can find a link to the
Mozilla advisories in the References section of this errata.

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0909&L=scientific-linux-errata&T=0&P=719
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca5e6a63"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/09");
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
if (rpm_check(release:"SL4", reference:"firefox-3.0.14-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nspr-4.7.5-1.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"nspr-devel-4.7.5-1.el4_8")) flag++;

if (rpm_check(release:"SL5", reference:"firefox-3.0.14-1.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-4.7.5-1.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-devel-4.7.5-1.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.0.14-1.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.0.14-1.el5_4")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-unstable-1.9.0.14-1.el5_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
