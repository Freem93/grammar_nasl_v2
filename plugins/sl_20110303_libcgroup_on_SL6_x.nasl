#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60979);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2011-1006", "CVE-2011-1022");

  script_name(english:"Scientific Linux Security Update : libcgroup on SL6.x i386/x86_64");
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
"A heap-based buffer overflow flaw was found in the way libcgroup
converted a list of user-provided controllers for a particular task
into an array of strings. A local attacker could use this flaw to
escalate their privileges via a specially crafted list of controllers.
(CVE-2011-1006)

It was discovered that libcgroup did not properly check the origin of
Netlink messages. A local attacker could use this flaw to send crafted
Netlink messages to the cgrulesengd daemon, causing it to put
processes into one or more existing control groups, based on the
attacker's choosing, possibly allowing the particular tasks to run
with more resources (memory, CPU, etc.) than originally intended.
(CVE-2011-1022)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=6903
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e018bd3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libcgroup, libcgroup-devel and / or libcgroup-pam
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/03");
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
if (rpm_check(release:"SL6", reference:"libcgroup-0.36.1-6.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"libcgroup-devel-0.36.1-6.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"libcgroup-pam-0.36.1-6.el6_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
