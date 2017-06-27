#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(100049);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/09 15:19:41 $");

  script_cve_id("CVE-2016-10195", "CVE-2016-10196", "CVE-2016-10197", "CVE-2017-5429", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5449", "CVE-2017-5451", "CVE-2017-5454", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467", "CVE-2017-5469");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL6.x, SL7.x i386/x86_64");
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
"This update upgrades Thunderbird to version 52.1.0.

Security Fix(es) :

  - Multiple flaws were found in the processing of malformed
    web content. A web page containing malicious content
    could cause Thunderbird to crash or, potentially,
    execute arbitrary code with the privileges of the user
    running Thunderbird. (CVE-2017-5429, CVE-2017-5433,
    CVE-2017-5435, CVE-2017-5436, CVE-2017-5459,
    CVE-2017-5466, CVE-2017-5432, CVE-2017-5434,
    CVE-2017-5438, CVE-2017-5439, CVE-2017-5440,
    CVE-2017-5441, CVE-2017-5442, CVE-2017-5443,
    CVE-2017-5444, CVE-2017-5446, CVE-2017-5447,
    CVE-2017-5454, CVE-2017-5460, CVE-2017-5464,
    CVE-2017-5465, CVE-2017-5469, CVE-2016-10195,
    CVE-2016-10196, CVE-2017-5445, CVE-2017-5449,
    CVE-2017-5451, CVE-2017-5467, CVE-2016-10197)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1705&L=scientific-linux-errata&F=&S=&P=1683
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd63725d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");
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
if (rpm_check(release:"SL6", reference:"thunderbird-52.1.0-1.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"thunderbird-debuginfo-52.1.0-1.el6_9")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"thunderbird-52.1.0-1.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"thunderbird-debuginfo-52.1.0-1.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
