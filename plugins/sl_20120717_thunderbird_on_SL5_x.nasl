#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61367);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2012-1948", "CVE-2012-1951", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1967");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL5.x, SL6.x i386/x86_64");
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
"Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed content.
Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2012-1948, CVE-2012-1951, CVE-2012-1952,
CVE-2012-1953, CVE-2012-1954, CVE-2012-1958, CVE-2012-1962,
CVE-2012-1967)

Malicious content could bypass same-compartment security wrappers
(SCSW) and execute arbitrary code with chrome privileges.
(CVE-2012-1959)

A flaw in the way Thunderbird called history.forward and history.back
could allow an attacker to conceal a malicious URL, possibly tricking
a user into believing they are viewing trusted content.
(CVE-2012-1955)

A flaw in a parser utility class used by Thunderbird to parse feeds
(such as RSS) could allow an attacker to execute arbitrary JavaScript
with the privileges of the user running Thunderbird. This issue could
have affected other Thunderbird components or add-ons that assume the
class returns sanitized input. (CVE-2012-1957)

A flaw in the way Thunderbird handled X-Frame-Options headers could
allow malicious content to perform a clickjacking attack.
(CVE-2012-1961)

A flaw in the way Content Security Policy (CSP) reports were generated
by Thunderbird could allow malicious content to steal a victim's OAuth
2.0 access tokens and OpenID credentials. (CVE-2012-1963)

A flaw in the way Thunderbird handled certificate warnings could allow
a man-in-the-middle attacker to create a crafted warning, possibly
tricking a user into accepting an arbitrary certificate as trusted.
(CVE-2012-1964)

A previous nss update introduced a mitigation for the CVE-2011-3389
flaw. For compatibility reasons, it remains disabled by default in the
nss packages. This update makes Thunderbird enable the mitigation by
default. It can be disabled by setting the NSS_SSL_CBC_RANDOM_IV
environment variable to 0 before launching Thunderbird.

Note: None of the issues in this advisory can be exploited by a
specially crafted HTML mail message as JavaScript is disabled by
default for mail messages. They could be exploited another way in
Thunderbird, for example, when viewing the full remote content of an
RSS feed.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 10.0.6 ESR, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=5041
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf45cc2e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
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
if (rpm_check(release:"SL5", reference:"thunderbird-10.0.6-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"thunderbird-debuginfo-10.0.6-1.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"thunderbird-10.0.6-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"thunderbird-debuginfo-10.0.6-1.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
