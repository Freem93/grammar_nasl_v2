#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60548);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/03/06 11:47:00 $");

  script_cve_id("CVE-2009-0037");

  script_name(english:"Scientific Linux Security Update : curl on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"David Kierznowski discovered a flaw in libcurl where it would not
differentiate between different target URLs when handling automatic
redirects. This caused libcurl to follow any new URL that it
understood, including the 'file://' URL type. This could allow a
remote server to force a local libcurl-using application to read a
local file instead of the remote one, possibly exposing local files
that were not meant to be exposed. (CVE-2009-0037)

Note: Applications using libcurl that are expected to follow redirects
to 'file://' protocol must now explicitly call curl_easy_setopt(3) and
set the newly introduced CURLOPT_REDIR_PROTOCOLS option as required.

All running applications using libcurl must be restarted for the
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0903&L=scientific-linux-errata&T=0&P=1977
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85b6faec"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected curl and / or curl-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"curl-7.10.6-9.rhel3")) flag++;
if (rpm_check(release:"SL3", reference:"curl-devel-7.10.6-9.rhel3")) flag++;

if (rpm_check(release:"SL4", cpu:"i386", reference:"curl-7.12.1-11.1.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"curl-7.12.1-11.1.el4_7.1")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"curl-devel-7.12.1-11.1.1")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"curl-devel-7.12.1-11.1.el4_7.1")) flag++;

if (rpm_check(release:"SL5", reference:"curl-7.15.5-2.1.el5_3.4")) flag++;
if (rpm_check(release:"SL5", reference:"curl-devel-7.15.5-2.1.el5_3.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
