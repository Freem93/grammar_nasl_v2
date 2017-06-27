#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60499);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-4313", "CVE-2008-4315");

  script_name(english:"Scientific Linux Security Update : tog-pegasus on SL5.x i386/x86_64");
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
"Scientific Linux defines additional security enhancements for
OpenGroup Pegasus WBEM services in addition to those defined by the
upstream OpenGroup Pegasus release.

After re-basing to version 2.7.0 of the OpenGroup Pegasus code, these
additional security enhancements were no longer being applied. As a
consequence, access to OpenPegasus WBEM services was not restricted to
the dedicated users. An attacker able to authenticate using a valid
user account could use this flaw to send requests to WBEM services.
(CVE-2008-4313)

Note: default SELinux policy prevents tog-pegasus from modifying
system files. This flaw's impact depends on whether or not tog-pegasus
is confined by SELinux, and on any additional CMPI providers installed
and enabled on a particular system.

Failed authentication attempts against the OpenPegasus CIM server were
not logged to the system log. An attacker could use this flaw to
perform password guessing attacks against a user account without
leaving traces in the system log. (CVE-2008-4315)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0811&L=scientific-linux-errata&T=0&P=2065
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b51355fe"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tog-pegasus and / or tog-pegasus-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"tog-pegasus-2.7.0-2.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"tog-pegasus-devel-2.7.0-2.el5_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
