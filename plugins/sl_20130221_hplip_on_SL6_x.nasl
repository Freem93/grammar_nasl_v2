#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65011);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/03/08 11:43:16 $");

  script_cve_id("CVE-2011-2722", "CVE-2013-0200");

  script_name(english:"Scientific Linux Security Update : hplip on SL6.x i386/x86_64");
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
"Several temporary file handling flaws were found in HPLIP. A local
attacker could use these flaws to perform a symbolic link attack,
overwriting arbitrary files accessible to a process using HPLIP.
(CVE-2013-0200, CVE-2011-2722)

The hplip packages have been upgraded to upstream version 3.12.4,
which provides a number of bug fixes and enhancements over the
previous version.

This update also fixes the following bugs :

  - Previously, the hpijs package required the obsolete
    cupsddk-drivers package, which was provided by the cups
    package. Under certain circumstances, this dependency
    caused hpijs installation to fail. This bug has been
    fixed and hpijs no longer requires cupsddk-drivers.

  - The configuration of the Scanner Access Now Easy (SANE)
    back end is located in the /etc/sane.d/dll.d/ directory,
    however, the hp-check utility checked only the
    /etc/sane.d/dll.conf file. Consequently, hp-check
    checked for correct installation, but incorrectly
    reported a problem with the way the SANE back end was
    installed. With this update, hp-check properly checks
    for installation problems in both locations as expected."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=818
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a42a9e1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"hpijs-3.12.4-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"hplip-3.12.4-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"hplip-common-3.12.4-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"hplip-debuginfo-3.12.4-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"hplip-gui-3.12.4-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"hplip-libs-3.12.4-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libsane-hpaio-3.12.4-4.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
