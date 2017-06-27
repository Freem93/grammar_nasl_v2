#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61306);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-3062", "CVE-2012-0467", "CVE-2012-0469", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0472", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479");

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

A flaw was found in Sanitiser for OpenType (OTS), used by Thunderbird
to help prevent potential exploits in malformed OpenType fonts.
Malicious content could cause Thunderbird to crash or, under certain
conditions, possibly execute arbitrary code with the privileges of the
user running Thunderbird. (CVE-2011-3062)

Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2012-0467, CVE-2012-0468, CVE-2012-0469)

Content containing a malicious Scalable Vector Graphics (SVG) image
file could cause Thunderbird to crash or, potentially, execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2012-0470)

A flaw was found in the way Thunderbird used its embedded Cairo
library to render certain fonts. Malicious content could cause
Thunderbird to crash or, under certain conditions, possibly execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2012-0472)

A flaw was found in the way Thunderbird rendered certain images using
WebGL. Malicious content could cause Thunderbird to crash or, under
certain conditions, possibly execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2012-0478)

A cross-site scripting (XSS) flaw was found in the way Thunderbird
handled certain multibyte character sets. Malicious content could
cause Thunderbird to run JavaScript code with the permissions of
different content. (CVE-2012-0471)

A flaw was found in the way Thunderbird rendered certain graphics
using WebGL. Malicious content could cause Thunderbird to crash.
(CVE-2012-0473)

A flaw in the built-in feed reader in Thunderbird allowed the Website
field to display the address of different content than the content the
user was visiting. An attacker could use this flaw to conceal a
malicious URL, possibly tricking a user into believing they are
viewing a trusted site, or allowing scripts to be loaded from the
attacker's site, possibly leading to cross-site scripting (XSS)
attacks. (CVE-2012-0474)

A flaw was found in the way Thunderbird decoded the ISO-2022-KR and
ISO-2022-CN character sets. Malicious content could cause Thunderbird
to run JavaScript code with the permissions of different content.
(CVE-2012-0477)

A flaw was found in the way the built-in feed reader in Thunderbird
handled RSS and Atom feeds. Invalid RSS or Atom content loaded over
HTTPS caused Thunderbird to display the address of said content, but
not the content. The previous content continued to be displayed. An
attacker could use this flaw to perform phishing attacks, or trick
users into thinking they are visiting the site reported by the Website
field, when the page is actually content controlled by an attacker.
(CVE-2012-0479)

Note: All issues except CVE-2012-0470, CVE-2012-0472, and
CVE-2011-3062 cannot be exploited by a specially crafted HTML mail
message as JavaScript is disabled by default for mail messages. It
could be exploited another way in Thunderbird, for example, when
viewing the full remote content of an RSS feed."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1204&L=scientific-linux-errata&T=0&P=2259
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0c078ed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/24");
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
if (rpm_check(release:"SL5", reference:"thunderbird-10.0.4-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"thunderbird-debuginfo-10.0.4-1.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"thunderbird-10.0.4-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"thunderbird-debuginfo-10.0.4-1.el6_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
