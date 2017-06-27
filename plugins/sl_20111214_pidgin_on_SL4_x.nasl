#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61208);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-4601", "CVE-2011-4602", "CVE-2011-4603");

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
"Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

An input sanitization flaw was found in the way the AOL Open System
for Communication in Realtime (OSCAR) protocol plug-in in Pidgin, used
by the AOL ICQ and AIM instant messaging systems, escaped certain
UTF-8 characters. A remote attacker could use this flaw to crash
Pidgin via a specially crafted OSCAR message. (CVE-2011-4601)

An input sanitization flaw was found in the way the Pidgin SILC
(Secure Internet Live Conferencing) protocol plug-in escaped certain
UTF-8 characters in channel messages. A remote attacker could use this
flaw to crash Pidgin via a specially crafted SILC message.
(CVE-2011-4603)

Multiple NULL pointer dereference flaws were found in the Jingle
extension of the Extensible Messaging and Presence Protocol (XMPP)
protocol plug-in in Pidgin. A remote attacker could use these flaws to
crash Pidgin via a specially crafted Jingle multimedia message.
(CVE-2011-4602)

All Pidgin users should upgrade to these updated packages, which
contain backported patches to resolve these issues. Pidgin must be
restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=2886
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6f5c4b4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/14");
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
if (rpm_check(release:"SL4", reference:"finch-2.6.6-10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"finch-devel-2.6.6-10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-2.6.6-10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-devel-2.6.6-10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-perl-2.6.6-10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-tcl-2.6.6-10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-2.6.6-10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-debuginfo-2.6.6-10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-devel-2.6.6-10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-perl-2.6.6-10.el4")) flag++;

if (rpm_check(release:"SL5", reference:"finch-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"finch-devel-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-devel-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-perl-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-tcl-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-debuginfo-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-devel-2.6.6-5.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-perl-2.6.6-5.el5_7.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
