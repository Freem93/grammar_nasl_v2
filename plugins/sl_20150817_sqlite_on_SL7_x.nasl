#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85502);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/10/05 13:44:22 $");

  script_cve_id("CVE-2015-3414", "CVE-2015-3415", "CVE-2015-3416");

  script_name(english:"Scientific Linux Security Update : sqlite on SL7.x x86_64");
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
"A flaw was found in the way SQLite handled dequoting of
collation-sequence names. A local attacker could submit a specially
crafted COLLATE statement that would crash the SQLite process, or have
other unspecified impacts. (CVE-2015-3414)

It was found that SQLite's sqlite3VdbeExec() function did not properly
implement comparison operators. A local attacker could submit a
specially crafted CHECK statement that would crash the SQLite process,
or have other unspecified impacts. (CVE-2015-3415)

It was found that SQLite's sqlite3VXPrintf() function did not properly
handle precision and width values during floating-point conversions. A
local attacker could submit a specially crafted SELECT statement that
would crash the SQLite process, or have other unspecified impacts.
(CVE-2015-3416)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=15216
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8c3b3c4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/18");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"lemon-3.7.17-6.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sqlite-3.7.17-6.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sqlite-debuginfo-3.7.17-6.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sqlite-devel-3.7.17-6.el7_1.1")) flag++;
if (rpm_check(release:"SL7", reference:"sqlite-doc-3.7.17-6.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"sqlite-tcl-3.7.17-6.el7_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
