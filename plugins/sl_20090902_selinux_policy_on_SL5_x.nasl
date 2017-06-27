#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60660);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_name(english:"Scientific Linux Security Update : selinux-policy on SL5.x i386/x86_64");
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
"These updated packages resolve several bugs in Security-Enhanced Linux
(SELinux) policy as shipped with Scientific Linux 5. The majority of
these bugs resulted in SELinux denying legitimate access.

The most prominent error came when tzdata was updated."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0910&L=scientific-linux-errata&T=0&P=1309
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97f91b1c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/02");
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
if (rpm_check(release:"SL5", reference:"libselinux-1.33.4-5.5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libselinux-devel-1.33.4-5.5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libselinux-python-1.33.4-5.5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libselinux-ruby-1.33.4-5.5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libselinux-utils-1.33.4-5.5.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libsemanage-1.9.1-4.4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libsemanage-devel-1.9.1-4.4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libsepol-1.15.2-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libsepol-devel-1.15.2-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"policycoreutils-1.33.12-14.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"policycoreutils-gui-1.33.12-14.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"policycoreutils-newrole-1.33.12-14.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-2.4.6-255.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-devel-2.4.6-255.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-minimum-2.4.6-255.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-mls-2.4.6-255.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-strict-2.4.6-255.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"selinux-policy-targeted-2.4.6-255.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
