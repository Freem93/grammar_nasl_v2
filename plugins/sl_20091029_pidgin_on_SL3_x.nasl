#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60686);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-2703", "CVE-2009-3083", "CVE-2009-3615");

  script_name(english:"Scientific Linux Security Update : pidgin on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"An invalid pointer dereference bug was found in the way the Pidgin
OSCAR protocol implementation processed lists of contacts. A remote
attacker could send a specially crafted contact list to a user running
Pidgin, causing Pidgin to crash. (CVE-2009-3615)

A NULL pointer dereference flaw was found in the way the Pidgin IRC
protocol plug-in handles IRC topics. A malicious IRC server could send
a specially crafted IRC TOPIC message, which once received by Pidgin,
would lead to a denial of service (Pidgin crash). (CVE-2009-2703) -
SL3 only

A NULL pointer dereference flaw was found in the way the Pidgin MSN
protocol plug-in handles improper MSNSLP invitations. A remote
attacker could send a specially crafted MSNSLP invitation request,
which once accepted by a valid Pidgin user, would lead to a denial of
service (Pidgin crash). (CVE-2009-3083) - SL3 only

Pidgin must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0911&L=scientific-linux-errata&T=0&P=79
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a95352a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/29");
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
if (rpm_check(release:"SL3", reference:"pidgin-1.5.1-6.el3")) flag++;

if (rpm_check(release:"SL4", reference:"finch-2.6.3-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"finch-devel-2.6.3-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-2.6.3-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-devel-2.6.3-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-perl-2.6.3-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-tcl-2.6.3-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-2.6.3-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-devel-2.6.3-2.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-perl-2.6.3-2.el4")) flag++;

if (rpm_check(release:"SL5", reference:"finch-2.6.3-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"finch-devel-2.6.3-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-2.6.3-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-devel-2.6.3-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-perl-2.6.3-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-tcl-2.6.3-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-2.6.3-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-devel-2.6.3-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-perl-2.6.3-2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
