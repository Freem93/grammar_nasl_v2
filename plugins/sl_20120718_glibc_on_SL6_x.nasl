#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61369);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/02/28 05:39:56 $");

  script_cve_id("CVE-2012-3404", "CVE-2012-3405", "CVE-2012-3406");

  script_name(english:"Scientific Linux Security Update : glibc on SL6.x i386/x86_64");
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
"The glibc packages provide the standard C and standard math libraries
used by multiple programs on the system. Without these libraries, the
Linux system cannot function properly.

Multiple errors in glibc's formatted printing functionality could
allow an attacker to bypass FORTIFY_SOURCE protections and execute
arbitrary code using a format string flaw in an application, even
though these protections are expected to limit the impact of such
flaws to an application abort. (CVE-2012-3404, CVE-2012-3405,
CVE-2012-3406)

This update also fixes the following bug :

  - A programming error caused an internal array of
    nameservers to be only partially initialized when the
    /etc/resolv.conf file contained IPv6 nameservers.
    Depending on the contents of a nearby structure, this
    could cause certain applications to terminate
    unexpectedly with a segmentation fault. The programming
    error has been fixed, which restores proper behavior
    with IPv6 nameservers listed in the /etc/resolv.conf
    file.

All users of glibc are advised to upgrade to these updated packages,
which contain backported patches to fix these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=5595
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5f13b80"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"glibc-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-common-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-common-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-devel-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-headers-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-static-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-utils-2.12-1.80.el6_3.3")) flag++;
if (rpm_check(release:"SL6", reference:"nscd-2.12-1.80.el6_3.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
