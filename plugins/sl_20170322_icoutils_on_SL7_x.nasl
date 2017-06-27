#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(97934);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/24 14:02:38 $");

  script_cve_id("CVE-2017-5208", "CVE-2017-5332", "CVE-2017-5333", "CVE-2017-6009", "CVE-2017-6010", "CVE-2017-6011");

  script_name(english:"Scientific Linux Security Update : icoutils on SL7.x x86_64");
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
"Security Fix(es) :

  - Multiple vulnerabilities were found in icoutils, in the
    wrestool program. An attacker could create a crafted
    executable that, when read by wrestool, could result in
    memory corruption leading to a crash or potential code
    execution. (CVE-2017-5208, CVE-2017-5333, CVE-2017-6009)

  - A vulnerability was found in icoutils, in the wrestool
    program. An attacker could create a crafted executable
    that, when read by wrestool, could result in failure to
    allocate memory or an over-large memcpy operation,
    leading to a crash. (CVE-2017-5332)

  - Multiple vulnerabilities were found in icoutils, in the
    icotool program. An attacker could create a crafted ICO
    or CUR file that, when read by icotool, could result in
    memory corruption leading to a crash or potential code
    execution. (CVE-2017-6010, CVE-2017-6011)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1703&L=scientific-linux-errata&F=&S=&P=9570
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f99f4b9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icoutils and / or icoutils-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"icoutils-0.31.3-1.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"icoutils-debuginfo-0.31.3-1.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
