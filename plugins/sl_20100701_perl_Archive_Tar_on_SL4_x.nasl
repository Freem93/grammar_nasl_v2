#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60811);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2007-4829");

  script_name(english:"Scientific Linux Security Update : perl-Archive-Tar on SL4.x, SL5.x i386/x86_64");
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
"Multiple directory traversal flaws were discovered in the Archive::Tar
module. A specially crafted tar file could cause a Perl script, using
the Archive::Tar module to extract the archive, to overwrite an
arbitrary file writable by the user running the script.
(CVE-2007-4829)

This package upgrades the Archive::Tar module to version 1.39_01.

All applications using the Archive::Tar module must be restarted for
this update to take effect.

Note: SL 40-45 needed perl-IO-Zlib"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1007&L=scientific-linux-errata&T=0&P=75
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?793749e8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-Archive-Tar and / or perl-IO-Zlib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/01");
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
if (rpm_check(release:"SL4", reference:"perl-Archive-Tar-1.39.1-1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"perl-IO-Zlib-1.04-4.2.el4")) flag++;

if (rpm_check(release:"SL5", reference:"perl-Archive-Tar-1.39.1-1.el5_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
