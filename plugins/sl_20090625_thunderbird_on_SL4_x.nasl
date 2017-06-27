#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60608);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-1303", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1392", "CVE-2009-1833", "CVE-2009-1836", "CVE-2009-1838");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several flaws were found in the processing of malformed HTML mail
content. An HTML mail message containing malicious content could cause
Thunderbird to crash or, potentially, execute arbitrary code as the
user running Thunderbird. (CVE-2009-1392, CVE-2009-1303,
CVE-2009-1305, CVE-2009-1833, CVE-2009-1838)

Several flaws were found in the way malformed HTML mail content was
processed. An HTML mail message containing malicious content could
execute arbitrary JavaScript in the context of the mail message,
possibly presenting misleading data to the user, or stealing sensitive
information such as login credentials. (CVE-2009-1306, CVE-2009-1307,
CVE-2009-1308, CVE-2009-1309)

A flaw was found in the way Thunderbird handled error responses
returned from proxy servers. If an attacker is able to conduct a
man-in-the-middle attack against a Thunderbird instance that is using
a proxy server, they may be able to steal sensitive information from
the site Thunderbird is displaying. (CVE-2009-1836)

Note: JavaScript support is disabled by default in Thunderbird. None
of the above issues are exploitable unless JavaScript is enabled.

All running instances of Thunderbird must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0906&L=scientific-linux-errata&T=0&P=1933
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19ae69b2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 79, 94, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/25");
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
if (rpm_check(release:"SL4", reference:"thunderbird-1.5.0.12-23.el4")) flag++;

if (rpm_check(release:"SL5", reference:"thunderbird-2.0.0.22-2.el5_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
