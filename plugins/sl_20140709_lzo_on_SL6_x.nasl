#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(76448);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/10 10:45:36 $");

  script_cve_id("CVE-2014-4607");

  script_name(english:"Scientific Linux Security Update : lzo on SL6.x i386/srpm/x86_64");
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
"An integer overflow flaw was found in the way the lzo library
decompressed certain archives compressed with the LZO algorithm. An
attacker could create a specially crafted LZO-compressed input that,
when decompressed by an application using the lzo library, would cause
that application to crash or, potentially, execute arbitrary code.
(CVE-2014-4607)

For the update to take effect, all services linked to the lzo library
must be restarted or the system rebooted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1407&L=scientific-linux-errata&T=0&P=702
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ae13054"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"lzo-2.03-3.1.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"lzo-debuginfo-2.03-3.1.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"lzo-debuginfo-2.03-3.1.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"lzo-devel-2.03-3.1.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"lzo-minilzo-2.03-3.1.el6_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
