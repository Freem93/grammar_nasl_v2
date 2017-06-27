#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61116);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-1929");

  script_name(english:"Scientific Linux Security Update : dovecot on SL4.x, SL5.x, SL6.x i386/x86_64");
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
"Dovecot is an IMAP server for Linux, UNIX, and similar operating
systems, primarily written with security in mind.

A denial of service flaw was found in the way Dovecot handled NULL
characters in certain header names. A mail message with specially
crafted headers could cause the Dovecot child process handling the
target user's connection to crash, blocking them from downloading the
message successfully and possibly leading to the corruption of their
mailbox. (CVE-2011-1929)

Users of dovecot are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue. After
installing the updated packages, the dovecot service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1108&L=scientific-linux-errata&T=0&P=2653
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd9f1bcd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/18");
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
if (rpm_check(release:"SL4", reference:"dovecot-0.99.11-10.EL4")) flag++;
if (rpm_check(release:"SL4", reference:"dovecot-debuginfo-0.99.11-10.EL4")) flag++;

if (rpm_check(release:"SL5", reference:"dovecot-1.0.7-7.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"dovecot-debuginfo-1.0.7-7.el5_7.1")) flag++;

if (rpm_check(release:"SL6", reference:"dovecot-2.0.9-2.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"dovecot-debuginfo-2.0.9-2.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"dovecot-devel-2.0.9-2.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"dovecot-mysql-2.0.9-2.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"dovecot-pgsql-2.0.9-2.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"dovecot-pigeonhole-2.0.9-2.el6_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
