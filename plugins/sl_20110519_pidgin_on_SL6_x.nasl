#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61045);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:26 $");

  script_cve_id("CVE-2011-1091");

  script_name(english:"Scientific Linux Security Update : pidgin on SL6.x i386/x86_64");
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

Multiple NULL pointer dereference flaws were found in the way the
Pidgin Yahoo! Messenger Protocol plug-in handled malformed YMSG
packets. A remote attacker could use these flaws to crash Pidgin via a
specially crafted notification message. (CVE-2011-1091)

Red Hat would like to thank the Pidgin project for reporting these
issues. Upstream acknowledges Marius Wachtler as the original
reporter.

This update also fixes the following bugs :

  - Previous versions of the pidgin package did not properly
    clear certain data structures used in libpurple/cipher.c
    when attempting to free them. Partial information could
    potentially be extracted from the incorrectly cleared
    regions of the previously freed memory. With this
    update, data structures are properly cleared when freed.
    (BZ#684685)

  - This erratum upgrades Pidgin to upstream version 2.7.9.
    For a list of all changes addressed in this upgrade,
    refer to http://developer.pidgin.im/wiki/ChangeLog
    (BZ#616917)

  - Some incomplete translations for the kn_IN and ta_IN
    locales have been corrected. (BZ#633860, BZ#640170)

Users of pidgin should upgrade to these updated packages, which
resolve these issues. Pidgin must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://developer.pidgin.im/wiki/ChangeLog"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=187
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?077e167b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=616917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=633860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=640170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=684685"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
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
if (rpm_check(release:"SL6", reference:"finch-2.7.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"finch-devel-2.7.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-2.7.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-devel-2.7.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-perl-2.7.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-tcl-2.7.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-2.7.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-debuginfo-2.7.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-devel-2.7.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-docs-2.7.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-perl-2.7.9-3.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
