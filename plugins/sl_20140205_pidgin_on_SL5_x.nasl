#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(72365);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/02/07 11:46:01 $");

  script_cve_id("CVE-2012-6152", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490", "CVE-2014-0020");

  script_name(english:"Scientific Linux Security Update : pidgin on SL5.x, SL6.x i386/x86_64");
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
"A heap-based buffer overflow flaw was found in the way Pidgin
processed certain HTTP responses. A malicious server could send a
specially crafted HTTP response, causing Pidgin to crash or
potentially execute arbitrary code with the permissions of the user
running Pidgin. (CVE-2013-6485)

Multiple heap-based buffer overflow flaws were found in several
protocol plug-ins in Pidgin (Gadu-Gadu, MXit, SIMPLE). A malicious
server could send a specially crafted message, causing Pidgin to crash
or potentially execute arbitrary code with the permissions of the user
running Pidgin. (CVE-2013-6487, CVE-2013-6489, CVE-2013-6490)

Multiple denial of service flaws were found in several protocol
plug-ins in Pidgin (Yahoo!, XMPP, MSN, stun, IRC). A remote attacker
could use these flaws to crash Pidgin by sending a specially crafted
message. (CVE-2012-6152, CVE-2013-6477, CVE-2013-6481, CVE-2013-6482,
CVE-2013-6484, CVE-2014-0020)

It was found that the Pidgin XMPP protocol plug-in did not verify the
origin of 'iq' replies. A remote attacker could use this flaw to spoof
an 'iq' reply, which could lead to injection of fake data or cause
Pidgin to crash via a NULL pointer dereference. (CVE-2013-6483)

A flaw was found in the way Pidgin parsed certain HTTP response
headers. A remote attacker could use this flaw to crash Pidgin via a
specially crafted HTTP response header. (CVE-2013-6479)

It was found that Pidgin crashed when a mouse pointer was hovered over
a long URL. A remote attacker could use this flaw to crash Pidgin by
sending a message containing a long URL string. (CVE-2013-6478)

Pidgin must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1402&L=scientific-linux-errata&T=0&P=955
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07969253"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"finch-2.6.6-32.el5")) flag++;
if (rpm_check(release:"SL5", reference:"finch-devel-2.6.6-32.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-2.6.6-32.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-devel-2.6.6-32.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-perl-2.6.6-32.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-tcl-2.6.6-32.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-2.6.6-32.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-debuginfo-2.6.6-32.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-devel-2.6.6-32.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-perl-2.6.6-32.el5")) flag++;

if (rpm_check(release:"SL6", reference:"finch-2.7.9-27.el6")) flag++;
if (rpm_check(release:"SL6", reference:"finch-devel-2.7.9-27.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-2.7.9-27.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-devel-2.7.9-27.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-perl-2.7.9-27.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-tcl-2.7.9-27.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-2.7.9-27.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-debuginfo-2.7.9-27.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-devel-2.7.9-27.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-docs-2.7.9-27.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-perl-2.7.9-27.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
