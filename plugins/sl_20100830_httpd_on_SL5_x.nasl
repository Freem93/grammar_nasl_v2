#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60847);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/07/20 01:56:57 $");

  script_cve_id("CVE-2010-1452", "CVE-2010-2791");

  script_name(english:"Scientific Linux Security Update : httpd on SL5.x i386/x86_64");
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
"A flaw was discovered in the way the mod_proxy module of the Apache
HTTP Server handled the timeouts of requests forwarded by a reverse
proxy to the back-end server. If the proxy was configured to reuse
existing back-end connections, it could return a response intended for
another user under certain timeout conditions, possibly leading to
information disclosure. (CVE-2010-2791)

A flaw was found in the way the mod_dav module of the Apache HTTP
Server handled certain requests. If a remote attacker were to send a
carefully crafted request to the server, it could cause the httpd
child process to crash. (CVE-2010-1452)

This update also fixes the following bugs :

  - numerous issues in the INFLATE filter provided by
    mod_deflate. 'Inflate error -5 on flush' errors may have
    been logged. This update upgrades mod_deflate to the
    newer upstream version from Apache HTTP Server 2.2.15.
    (BZ#625435)

  - the response would be corrupted if mod_filter applied
    the DEFLATE filter to a resource requiring a subrequest
    with an internal redirect. (BZ#625451)

  - the OID() function used in the mod_ssl 'SSLRequire'
    directive did not correctly evaluate extensions of an
    unknown type. (BZ#625452)

After installing the updatedpackages, the httpd daemon must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1008&L=scientific-linux-errata&T=0&P=3145
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1286af7f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=625435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=625451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=625452"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/30");
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
if (rpm_check(release:"SL5", reference:"httpd-2.2.3-43.sl5.3")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-devel-2.2.3-43.sl5.3")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-manual-2.2.3-43.sl5.3")) flag++;
if (rpm_check(release:"SL5", reference:"mod_ssl-2.2.3-43.sl5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
