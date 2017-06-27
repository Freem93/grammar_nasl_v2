#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60765);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2010-0734");

  script_name(english:"Scientific Linux Security Update : curl on SL5.x i386/x86_64");
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
"Wesley Miaw discovered that when deflate compression was used, libcurl
could call the registered write callback function with data exceeding
the documented limit. A malicious server could use this flaw to crash
an application using libcurl or, potentially, execute arbitrary code.
Note: This issue only affected applications using libcurl that rely on
the documented data size limit, and that copy the data to the
insufficiently sized buffer. (CVE-2010-0734)

This update also fixes the following bugs :

  - when using curl to upload a file, if the connection was
    broken or reset by the server during the transfer, curl
    immediately started using 100% CPU and failed to
    acknowledge that the transfer had failed. With this
    update, curl displays an appropriate error message and
    exits when an upload fails mid-transfer due to a broken
    or reset connection. (BZ#479967)

  - libcurl experienced a segmentation fault when attempting
    to reuse a connection after performing GSS-negotiate
    authentication, which in turn caused the curl program to
    crash. This update fixes this bug so that reused
    connections are able to be successfully established even
    after GSS-negotiate authentication has been performed.
    (BZ#517199)

As well, this update adds the following enhancements :

  - curl now supports loading Certificate Revocation Lists
    (CRLs) from a Privacy Enhanced Mail (PEM) file. When
    curl attempts to access sites that have had their
    certificate revoked in a CRL, curl refuses access to
    those sites. (BZ#532069)

  - the curl(1) manual page has been updated to clarify that
    the '--socks4' and '--socks5' options do not work with
    the IPv6, FTPS, or LDAP protocols. (BZ#473128)

  - the curl utility's program help, which is accessed by
    running 'curl -h', has been updated with descriptions
    for the '--ftp-account' and '--ftp-alternative-to-user'
    options. (BZ#517084)

All running applications using libcurl must be restarted for the
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1004&L=scientific-linux-errata&T=0&P=1035
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82cea57d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=473128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=479967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=517084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=517199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=532069"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected curl and / or curl-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
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
if (rpm_check(release:"SL5", reference:"curl-7.15.5-9.el5")) flag++;
if (rpm_check(release:"SL5", reference:"curl-devel-7.15.5-9.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
