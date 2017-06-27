#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60993);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_name(english:"Scientific Linux Security Update : firefox on SL4.x, SL5.x, SL6.x i386/x86_64");
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
"This erratum blacklists a small number of HTTPS certificates.
(BZ#689430)

These updated firefox packages also fixes the following bug :

  - Prior to this update, some Java applets would fail to
    load in the 3.6.14 version of Firefox. In this
    newly-released version (Firefox 3.6.15), Java applets no
    longer fail to load. (BZ#682251, BZ#682252, BZ#682253)

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=9894
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ecdaa72"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=682251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=682252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=682253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=689430"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected firefox, xulrunner and / or xulrunner-devel
packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"firefox-3.6.15-2.el4")) flag++;

if (rpm_check(release:"SL5", reference:"firefox-3.6.15-1.el5_6")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-1.9.2.15-2.el5_6")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-1.9.2.15-2.el5_6")) flag++;

if (rpm_check(release:"SL6", reference:"firefox-3.6.15-2.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-1.9.2.15-2.el6_0")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-devel-1.9.2.15-2.el6_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
