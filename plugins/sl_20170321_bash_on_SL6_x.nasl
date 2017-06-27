#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(99214);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/06 13:23:47 $");

  script_cve_id("CVE-2016-0634", "CVE-2016-7543", "CVE-2016-9401");

  script_name(english:"Scientific Linux Security Update : bash on SL6.x i386/x86_64");
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

  - An arbitrary command injection flaw was found in the way
    bash processed the hostname value. A malicious DHCP
    server could use this flaw to execute arbitrary commands
    on the DHCP client machines running bash under specific
    circumstances. (CVE-2016-0634)

  - An arbitrary command injection flaw was found in the way
    bash processed the SHELLOPTS and PS4 environment
    variables. A local, authenticated attacker could use
    this flaw to exploit poorly written setuid programs to
    elevate their privileges under certain circumstances.
    (CVE-2016-7543)

  - A denial of service flaw was found in the way bash
    handled popd commands. A poorly written shell script
    could cause bash to crash resulting in a local denial of
    service limited to a specific bash session.
    (CVE-2016-9401)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1704&L=scientific-linux-errata&F=&S=&P=5255
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4e99ec6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bash, bash-debuginfo and / or bash-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");
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
if (rpm_check(release:"SL6", reference:"bash-4.1.2-48.el6")) flag++;
if (rpm_check(release:"SL6", reference:"bash-debuginfo-4.1.2-48.el6")) flag++;
if (rpm_check(release:"SL6", reference:"bash-doc-4.1.2-48.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
