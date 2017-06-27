#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60194);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2007-1362", "CVE-2007-1558", "CVE-2007-1562", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");

  script_name(english:"Scientific Linux Security Update : seamonkey on SL4.x, SL3.x i386/x86_64");
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
"Several flaws were found in the way SeaMonkey processed certain
malformed JavaScript code. A web page containing malicious JavaScript
code could cause SeaMonkey to crash or potentially execute arbitrary
code as the user running SeaMonkey. (CVE-2007-2867, CVE-2007-2868)

A flaw was found in the way SeaMonkey handled certain FTP PASV
commands. A malicious FTP server could use this flaw to perform a
rudimentary port-scan of machines behind a user's firewall.
(CVE-2007-1562)

Several denial of service flaws were found in the way SeaMonkey
handled certain form and cookie data. A malicious website that is able
to set arbitrary form and cookie data could prevent SeaMonkey from
functioning properly. (CVE-2007-1362, CVE-2007-2869)

A flaw was found in the way SeaMonkey processed certain APOP
authentication requests. By sending certain responses when SeaMonkey
attempted to authenticate against an APOP server, a remote attacker
could potentially acquire certain portions of a user's authentication
credentials. (CVE-2007-1558)

A flaw was found in the way SeaMonkey handled the addEventListener
JavaScript method. A malicious website could use this method to access
or modify sensitive data from another website. (CVE-2007-2870)

A flaw was found in the way SeaMonkey displayed certain web content. A
malicious web page could generate content that would overlay user
interface elements such as the hostname and security indicators,
tricking users into thinking they are visiting a different site.
(CVE-2007-2871)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0706&L=scientific-linux-errata&T=0&P=584
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa63a4a1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/30");
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
if (rpm_check(release:"SL3", reference:"seamonkey-1.0.9-0.1.SL3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-chat-1.0.9-0.1.SL3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-devel-1.0.9-0.1.SL3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-dom-inspector-1.0.9-0.1.SL3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-js-debugger-1.0.9-0.1.SL3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-mail-1.0.9-0.1.SL3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-nspr-1.0.9-0.1.SL3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-nspr-devel-1.0.9-0.1.SL3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-nss-1.0.9-0.1.SL3")) flag++;
if (rpm_check(release:"SL3", reference:"seamonkey-nss-devel-1.0.9-0.1.SL3")) flag++;

if (rpm_check(release:"SL4", reference:"devhelp-0.10-0.8.el4")) flag++;
if (rpm_check(release:"SL4", reference:"devhelp-devel-0.10-0.8.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-1.0.9-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-chat-1.0.9-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-devel-1.0.9-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-dom-inspector-1.0.9-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-js-debugger-1.0.9-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-mail-1.0.9-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-nspr-1.0.9-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-nspr-devel-1.0.9-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-nss-1.0.9-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"seamonkey-nss-devel-1.0.9-2.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
