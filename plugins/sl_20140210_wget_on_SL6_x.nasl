#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(72421);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/11 12:01:56 $");

  script_cve_id("CVE-2010-2252");

  script_name(english:"Scientific Linux Security Update : wget on SL6.x i386/x86_64");
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
"It was discovered that wget used a file name provided by the server
when saving a downloaded file. This could cause wget to create a file
with a different name than expected, possibly allowing the server to
execute arbitrary code on the client. (CVE-2010-2252)

Note: With this update, wget always uses the last component of the
original URL as the name for the downloaded file. Previous behavior of
using the server provided name or the last component of the redirected
URL when creating files can be re-enabled by using the
'--trust-server-names' command line option, or by setting
'trust_server_names=on' in the wget start-up file.

This update also fixes the following bugs :

  - Prior to this update, the wget package did not recognize
    HTTPS SSL certificates with alternative names
    (subjectAltName) specified in the certificate as valid.
    As a consequence, running the wget command failed with a
    certificate error. This update fixes wget to recognize
    such certificates as valid."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1402&L=scientific-linux-errata&T=0&P=1085
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b94d71e2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wget and / or wget-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/11");
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
if (rpm_check(release:"SL6", reference:"wget-1.12-1.11.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"wget-debuginfo-1.12-1.11.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
