#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60738);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2010-0277", "CVE-2010-0420", "CVE-2010-0423");

  script_name(english:"Scientific Linux Security Update : pidgin on SL4.x, SL5.x i386/x86_64");
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
"CVE-2010-0277 pidgin MSN protocol plugin memory corruption

CVE-2010-0420 pidgin: Finch XMPP MUC Crash

CVE-2010-0423 pidgin: Smiley Denial of Service

An input sanitization flaw was found in the way Pidgin's MSN protocol
implementation handled MSNSLP invitations. A remote attacker could
send a specially crafted INVITE request that would cause a denial of
service (memory corruption and Pidgin crash). (CVE-2010-0277)

A denial of service flaw was found in Finch's XMPP chat
implementation, when using multi-user chat. If a Finch user in a
multi-user chat session were to change their nickname to contain the
HTML 'br' element, it would cause Finch to crash. (CVE-2010-0420)

A denial of service flaw was found in the way Pidgin processed
emoticon images. A remote attacker could flood the victim with
emoticon images during mutual communication, leading to excessive CPU
use. (CVE-2010-0423)

Pidgin must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1002&L=scientific-linux-errata&T=0&P=1520
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e874127e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/18");
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
if (rpm_check(release:"SL4", reference:"finch-2.6.6-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"finch-devel-2.6.6-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-2.6.6-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-devel-2.6.6-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-perl-2.6.6-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-tcl-2.6.6-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-2.6.6-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-devel-2.6.6-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-perl-2.6.6-1.el4")) flag++;

if (rpm_check(release:"SL5", reference:"finch-2.6.6-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"finch-devel-2.6.6-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-2.6.6-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-devel-2.6.6-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-perl-2.6.6-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-tcl-2.6.6-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-2.6.6-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-devel-2.6.6-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-perl-2.6.6-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
