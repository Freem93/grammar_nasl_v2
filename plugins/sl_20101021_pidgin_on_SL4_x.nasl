#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60876);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-1624", "CVE-2010-3711");

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
"Multiple NULL pointer dereference flaws were found in the way Pidgin
handled Base64 decoding. A remote attacker could use these flaws to
crash Pidgin if the target Pidgin user was using the Yahoo! Messenger
Protocol, MSN, MySpace, or Extensible Messaging and Presence Protocol
(XMPP) protocol plug-ins, or using the Microsoft NT LAN Manager (NTLM)
protocol for authentication. (CVE-2010-3711)

A NULL pointer dereference flaw was found in the way the Pidgin MSN
protocol plug-in processed custom emoticon messages. A remote attacker
could use this flaw to crash Pidgin by sending specially crafted
emoticon messages during mutual communication. (CVE-2010-1624)

Pidgin must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1010&L=scientific-linux-errata&T=0&P=2639
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b05ba23"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/21");
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
if (rpm_check(release:"SL4", reference:"finch-2.6.6-5.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"finch-devel-2.6.6-5.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-2.6.6-5.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-devel-2.6.6-5.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-perl-2.6.6-5.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"libpurple-tcl-2.6.6-5.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-2.6.6-5.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-devel-2.6.6-5.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"pidgin-perl-2.6.6-5.el4_8")) flag++;

if (rpm_check(release:"SL5", reference:"finch-2.6.6-5.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"finch-devel-2.6.6-5.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-2.6.6-5.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-devel-2.6.6-5.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-perl-2.6.6-5.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-tcl-2.6.6-5.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-2.6.6-5.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-devel-2.6.6-5.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-perl-2.6.6-5.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
