#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(62304);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/09/26 10:56:15 $");

  script_name(english:"Scientific Linux Security Update : yum-autoupdate update on SL5.x, SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Scientific Linux team was made aware of a problem with the use of
temp files in the yum-autoupdate script by Elias Persson. The problem
should be corrected in these packages.

These packages also include some minor feature updates for each
release.

For SL5, the script now includes the 'PRERUN' and 'POSTRUN'
functionality first provided in SL5.8 and SL6. The script is still
configured as before, in the /etc/yum.d/ directory. The new features
were added to the /etc/yum.d/yum.cron.updateexec config file.

For SL6, the package now includes an augeas lense for possible
automated configuration. Augeas is a configuration file editing tool.
This lense allows augeas to read your configuration file so that you
can customize it through that program. Typically augeas is used for
automated configuration file edits. This lense should allow you to
script out any changes you wish to make at your site. Automated tools
such as puppet can use augeas as native tool for configuration file
edits.

These packages were placed in testing for two weeks before their
release. There were no reported problems."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1209&L=scientific-linux-errata&T=0&P=3908
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c81c730c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected yum-autoupdate package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/26");
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
if (rpm_check(release:"SL5", reference:"yum-autoupdate-1.2-2.SL")) flag++;

if (rpm_check(release:"SL6", reference:"yum-autoupdate-2-5.0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
