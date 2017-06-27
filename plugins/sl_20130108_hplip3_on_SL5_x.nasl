#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(63596);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/17 14:07:22 $");

  script_cve_id("CVE-2011-2722");

  script_name(english:"Scientific Linux Security Update : hplip3 on SL5.x i386/x86_64");
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
"It was found that the HP CUPS (Common UNIX Printing System) fax filter
in HPLIP created a temporary file in an insecure way. A local attacker
could use this flaw to perform a symbolic link attack, overwriting
arbitrary files accessible to a process using the fax filter (such as
the hp3-sendfax tool). (CVE-2011-2722)

This update also fixes the following bug :

  - Previous modifications of the hplip3 package to allow it
    to be installed alongside the original hplip package
    introduced several problems to fax support; for example,
    the hp-sendfax utility could become unresponsive. These
    problems have been fixed with this update."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=2442
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?140e44c6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
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
if (rpm_check(release:"SL5", reference:"hpijs3-3.9.8-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"hplip3-3.9.8-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"hplip3-common-3.9.8-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"hplip3-debuginfo-3.9.8-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"hplip3-gui-3.9.8-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"hplip3-libs-3.9.8-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libsane-hpaio3-3.9.8-15.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
