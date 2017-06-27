#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85498);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/08/28 13:51:53 $");

  script_cve_id("CVE-2013-7424");

  script_name(english:"Scientific Linux Security Update : glibc on SL5.x i386/x86_64");
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
"An invalid free flaw was found in glibc's getaddrinfo() function when
used with the AI_IDN flag. A remote attacker able to make an
application call this function could use this flaw to execute
arbitrary code with the permissions of the user running the
application. Note that this flaw only affected applications using
glibc compiled with libidn support. (CVE-2013-7424)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=16270
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4c54550"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

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
if (rpm_check(release:"SL5", reference:"glibc-2.5-123.el5_11.3")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-common-2.5-123.el5_11.3")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-debuginfo-2.5-123.el5_11.3")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-debuginfo-common-2.5-123.el5_11.3")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-devel-2.5-123.el5_11.3")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-headers-2.5-123.el5_11.3")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-utils-2.5-123.el5_11.3")) flag++;
if (rpm_check(release:"SL5", reference:"nscd-2.5-123.el5_11.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
