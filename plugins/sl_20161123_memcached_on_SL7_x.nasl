#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(95866);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/16 15:05:10 $");

  script_cve_id("CVE-2016-8704", "CVE-2016-8705", "CVE-2016-8706");

  script_name(english:"Scientific Linux Security Update : memcached on SL7.x x86_64");
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

  - Two integer overflow flaws, leading to heap-based buffer
    overflows, were found in the memcached binary protocol.
    An attacker could create a specially crafted message
    that would cause the memcached server to crash or,
    potentially, execute arbitrary code. (CVE-2016-8704,
    CVE-2016-8705)

  - An integer overflow flaw, leading to a heap-based buffer
    overflow, was found in memcached's parsing of SASL
    authentication messages. An attacker could create a
    specially crafted message that would cause the memcached
    server to crash or, potentially, execute arbitrary code.
    (CVE-2016-8706)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=14560
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?980b3047"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected memcached, memcached-debuginfo and / or
memcached-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"memcached-1.4.15-10.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"memcached-debuginfo-1.4.15-10.el7_3.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"memcached-devel-1.4.15-10.el7_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
