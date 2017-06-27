#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85195);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/04 14:00:09 $");

  script_cve_id("CVE-2014-9273");

  script_name(english:"Scientific Linux Security Update : hivex on SL6.x x86_64");
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
"It was found that hivex attempted to read, and possibly write, beyond
its allocated buffer when reading a hive file with a very small size
or with a truncated or improperly formatted content. An attacker able
to supply a specially crafted hive file to an application using the
hivex library could possibly use this flaw to execute arbitrary code
with the privileges of the user running that application.
(CVE-2014-9273)

This update also fixes the following bug :

  - The hivex(3) man page previously contained a
    typographical error. This update fixes the typo."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=6188
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ca6c762"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"hivex-1.3.3-4.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"hivex-debuginfo-1.3.3-4.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"hivex-devel-1.3.3-4.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"ocaml-hivex-1.3.3-4.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"ocaml-hivex-devel-1.3.3-4.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"perl-hivex-1.3.3-4.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"python-hivex-1.3.3-4.3.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
