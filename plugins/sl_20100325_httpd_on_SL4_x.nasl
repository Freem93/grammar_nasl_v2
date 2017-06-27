#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60753);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/07/20 01:56:57 $");

  script_cve_id("CVE-2010-0434");

  script_name(english:"Scientific Linux Security Update : httpd on SL4.x i386/x86_64");
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
"CVE-2010-0434 httpd: request header information leak

A use-after-free flaw was discovered in the way the Apache HTTP Server
handled request headers in subrequests. In configurations where
subrequests are used, a multithreaded MPM (Multi-Processing Module)
could possibly leak information from other requests in request
replies. (CVE-2010-0434)

This update also fixes the following bug :

  - a bug was found in the mod_dav module. If a PUT request
    for an existing file failed, that file would be
    unexpectedly deleted and a 'Could not get next bucket
    brigade' error logged. With this update, failed PUT
    requests no longer cause mod_dav to delete files, which
    resolves this issue. (BZ#572932)

As well, this update adds the following enhancement :

  - with the updated openssl packages from RHSA-2010:0163
    installed, mod_ssl will refuse to renegotiate a TLS/SSL
    connection with an unpatched client that does not
    support RFC 5746. This update adds the
    'SSLInsecureRenegotiation' configuration directive. If
    this directive is enabled, mod_ssl will renegotiate
    insecurely with unpatched clients. (BZ#575805)

Refer to the following Red Hat Knowledgebase article for more details
about the changed mod_ssl behavior:
http://kbase.redhat.com/faq/docs/DOC-20491

After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kbase.redhat.com/faq/docs/DOC-20491"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1003&L=scientific-linux-errata&T=0&P=2999
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9411e9c7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=572932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=575805"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/25");
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
if (rpm_check(release:"SL4", reference:"httpd-2.0.52-41.sl4.7")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-devel-2.0.52-41.sl4.7")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-manual-2.0.52-41.sl4.7")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-suexec-2.0.52-41.sl4.7")) flag++;
if (rpm_check(release:"SL4", reference:"mod_ssl-2.0.52-41.sl4.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
