#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65565);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274");

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
"A stack-based buffer overflow flaw was found in the Pidgin MXit
protocol plug-in. A malicious server or a remote attacker could use
this flaw to crash Pidgin by sending a specially crafted HTTP request.
(CVE-2013-0272)

A buffer overflow flaw was found in the Pidgin Sametime protocol
plug-in. A malicious server or a remote attacker could use this flaw
to crash Pidgin by sending a specially crafted username.
(CVE-2013-0273)

A buffer overflow flaw was found in the way Pidgin processed certain
UPnP responses. A remote attacker could send a specially crafted UPnP
response that, when processed, would crash Pidgin. (CVE-2013-0274)

Pidgin must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=4899
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84aeb080"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"finch-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"finch-devel-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-devel-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-perl-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-tcl-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-debuginfo-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-devel-2.6.6-17.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-perl-2.6.6-17.el5_9.1")) flag++;

if (rpm_check(release:"SL6", reference:"finch-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"finch-devel-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-devel-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-perl-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-tcl-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-debuginfo-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-devel-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-docs-2.7.9-10.el6_4.1")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-perl-2.7.9-10.el6_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
