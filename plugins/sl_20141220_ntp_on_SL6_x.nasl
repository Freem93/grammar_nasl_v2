#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(80164);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/11/01 04:40:11 $");

  script_cve_id("CVE-2014-9293", "CVE-2014-9294", "CVE-2014-9295", "CVE-2014-9296");

  script_name(english:"Scientific Linux Security Update : ntp on SL6.x, SL7.x i386/x86_64");
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
"Multiple buffer overflow flaws were discovered in ntpd's
crypto_recv(), ctl_putdata(), and configure() functions. A remote
attacker could use either of these flaws to send a specially crafted
request packet that could crash ntpd or, potentially, execute
arbitrary code with the privileges of the ntp user. Note: the
crypto_recv() flaw requires non- default configurations to be active,
while the ctl_putdata() flaw, by default, can only be exploited via
local attackers, and the configure() flaw requires additional
authentication to exploit. (CVE-2014-9295)

It was found that ntpd automatically generated weak keys for its
internal use if no ntpdc request authentication key was specified in
the ntp.conf configuration file. A remote attacker able to match the
configured IP restrictions could guess the generated key, and possibly
use it to send ntpdc query or configuration requests. (CVE-2014-9293)

It was found that ntp-keygen used a weak method for generating MD5
keys. This could possibly allow an attacker to guess generated MD5
keys that could then be used to spoof an NTP client or server. Note:
it is recommended to regenerate any MD5 keys that had explicitly been
generated with ntp-keygen; the default installation does not contain
such keys). (CVE-2014-9294)

A missing return statement in the receive() function could potentially
allow a remote attacker to bypass NTP's authentication mechanism.
(CVE-2014-9296)

After installing the update, the ntpd daemon will restart
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=3720
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1eb916f4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"ntp-4.2.6p5-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-debuginfo-4.2.6p5-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-doc-4.2.6p5-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-perl-4.2.6p5-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"ntpdate-4.2.6p5-2.el6_6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntp-4.2.6p5-19.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntp-debuginfo-4.2.6p5-19.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"ntp-doc-4.2.6p5-19.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"ntp-perl-4.2.6p5-19.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntpdate-4.2.6p5-19.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sntp-4.2.6p5-19.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
