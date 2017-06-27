#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(86615);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/06/13 13:30:10 $");

  script_cve_id("CVE-2015-5300", "CVE-2015-7704");

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
"It was discovered that ntpd as a client did not correctly check
timestamps in Kiss-of-Death packets. A remote attacker could use this
flaw to send a crafted Kiss-of-Death packet to an ntpd client that
would increase the client's polling interval value, and effectively
disable synchronization with the server. (CVE-2015-7704)

It was found that ntpd did not correctly implement the threshold
limitation for the '-g' option, which is used to set the time without
any restrictions. A man-in-the-middle attacker able to intercept NTP
traffic between a connecting client and an NTP server could use this
flaw to force that client to make multiple steps larger than the panic
threshold, effectively changing the time to an arbitrary value.
(CVE-2015-5300)

After installing the update, the ntpd daemon will restart
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1510&L=scientific-linux-errata&F=&S=&P=5166
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ffa7ffd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"ntp-4.2.6p5-5.el6_7.2")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-debuginfo-4.2.6p5-5.el6_7.2")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-doc-4.2.6p5-5.el6_7.2")) flag++;
if (rpm_check(release:"SL6", reference:"ntp-perl-4.2.6p5-5.el6_7.2")) flag++;
if (rpm_check(release:"SL6", reference:"ntpdate-4.2.6p5-5.el6_7.2")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntp-4.2.6p5-19.el7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntp-debuginfo-4.2.6p5-19.el7_1.3")) flag++;
if (rpm_check(release:"SL7", reference:"ntp-doc-4.2.6p5-19.el7_1.3")) flag++;
if (rpm_check(release:"SL7", reference:"ntp-perl-4.2.6p5-19.el7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ntpdate-4.2.6p5-19.el7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sntp-4.2.6p5-19.el7_1.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
