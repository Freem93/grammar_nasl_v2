#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60617);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/06 11:47:00 $");

  script_name(english:"Scientific Linux Security Update : GPG-RPM key on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"Updating the GPG keys in the release to include a Scientific Linux RPM
signing key to sign the rpm's with. We will start using this new key,
and stop using Connie or Troy's personal GPG Keys for signing rpm's.

This is labeled as Moderate because those machines that have gpg
checking turned on will be unable update their security errata until
this update has been done.

Note1: This is not because any keys have been compromised, or a
break-in. This is because we are changing the model we use for signing
rpms."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0907&L=scientific-linux-errata&T=0&P=1136
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64f99354"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"sl-release-3.0.9-7.10")) flag++;

if (rpm_check(release:"SL4", cpu:"x86_64", reference:"sl-release-4.0-6")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"yum-conf-40-11.SL")) flag++;
if (rpm_check(release:"SL4", reference:"yum-conf-4x-1-8.SL")) flag++;

if (rpm_check(release:"SL5", cpu:"x86_64", reference:"sl-release-5.0-5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"yum-conf-50-5.SL")) flag++;
if (rpm_check(release:"SL5", reference:"yum-conf-5x-1-7.SL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
