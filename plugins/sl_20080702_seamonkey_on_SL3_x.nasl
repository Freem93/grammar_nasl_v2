#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60435);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810", "CVE-2008-2811");

  script_name(english:"Scientific Linux Security Update : seamonkey on SL3.x, SL4.x i386/x86_64");
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
"Multiple flaws were found in the processing of malformed JavaScript
content. A web page containing such malicious content could cause
SeaMonkey to crash or, potentially, execute arbitrary code as the user
running SeaMonkey. (CVE-2008-2801, CVE-2008-2802, CVE-2008-2803)

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause SeaMonkey to crash
or, potentially, execute arbitrary code as the user running SeaMonkey.
(CVE-2008-2798, CVE-2008-2799, CVE-2008-2811)

Several flaws were found in the way malformed web content was
displayed. A web page containing specially crafted content could
potentially trick a SeaMonkey user into surrendering sensitive
information. (CVE-2008-2800)

Two local file disclosure flaws were found in SeaMonkey. A web page
containing malicious content could cause SeaMonkey to reveal the
contents of a local file to a remote attacker. (CVE-2008-2805,
CVE-2008-2810)

A flaw was found in the way a malformed .properties file was processed
by SeaMonkey. A malicious extension could read uninitialized memory,
possibly leaking sensitive data to the extension. (CVE-2008-2807)

A flaw was found in the way SeaMonkey escaped a listing of local file
names. If a user could be tricked into listing a local directory
containing malicious file names, arbitrary JavaScript could be run
with the permissions of the user running SeaMonkey. (CVE-2008-2808)

A flaw was found in the way SeaMonkey displayed information about
self-signed certificates. It was possible for a self-signed
certificate to contain multiple alternate name entries, which were not
all displayed to the user, allowing them to mistakenly extend trust to
an unknown site. (CVE-2008-2809)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0807&L=scientific-linux-errata&T=0&P=190
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?371ab25c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 79, 200, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/02");
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
if (rpm_check(release:"SL3", reference:"seamonkey-1.0.9-0.20.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-chat-1.0.9-0.20.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-devel-1.0.9-0.20.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-dom-inspector-1.0.9-0.20.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-js-debugger-1.0.9-0.20.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-mail-1.0.9-0.20.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-nspr-1.0.9-0.20.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-nspr-devel-1.0.9-0.20.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-nss-1.0.9-0.20.el3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-nss-devel-1.0.9-0.20.el3")) flag++;

if (rpm_check(release:"SL4", reference:"seamonkey-1.0.9-16.3.el4_6")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-chat-1.0.9-16.3.el4_6")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-devel-1.0.9-16.3.el4_6")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-dom-inspector-1.0.9-16.3.el4_6")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-js-debugger-1.0.9-16.3.el4_6")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-mail-1.0.9-16.3.el4_6")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-nspr-1.0.9-16.3.el4_6")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-nspr-devel-1.0.9-16.3.el4_6")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-nss-1.0.9-16.3.el4_6")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-nss-devel-1.0.9-16.3.el4_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
