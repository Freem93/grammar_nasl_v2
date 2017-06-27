#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60407);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2007-5794");

  script_name(english:"Scientific Linux Security Update : nss_ldap on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A race condition was discovered in nss_ldap which affected certain
applications which make LDAP connections, such as Dovecot. This could
cause nss_ldap to answer a request for information about one user with
information about a different user. (CVE-2007-5794)

In addition, these updated packages fix the following bugs :

  - a build error prevented the nss_ldap module from being
    able to use DNS to discover the location of a directory
    server. For example, when the /etc/nsswitch.conf
    configuration file was configured to use 'ldap', but no
    'host' or 'uri' option was configured in the
    /etc/ldap.conf configuration file, no directory server
    was contacted, and no results were returned.

  - the 'port' option in the /etc/ldap.conf configuration
    file on client machines was ignored. For example, if a
    directory server which you were attempting to use was
    listening on a non-default port (i.e. not ports 389 or
    636), it was only possible to use that directory server
    by including the port number in the 'uri' option. In
    this updated package, the 'port' option works as
    expected.

  - pam_ldap failed to change an expired password if it had
    to follow a referral to do so, which could occur, for
    example, when using a slave directory server in a
    replicated environment. An error such as the following
    occurred after entering a new password: 'LDAP password
    information update failed: Can't contact LDAP server
    Insufficient 'write' privilege to the 'userPassword'
    attribute'

This has been resolved in this updated package.

  - when the 'pam_password exop_send_old' password-change
    method was configured in the /etc/ldap.conf
    configuration file, a logic error in the pam_ldap module
    caused client machines to attempt to change a user's
    password twice. First, the pam_ldap module attempted to
    change the password using the 'exop' request, and then
    again using an LDAP modify request.

  - on Red Hat Enterprise Linux 5.1, rebuilding
    nss_ldap-253-5.el5 when the krb5-*-1.6.1-17.el5 packages
    were installed failed due to an error such as the
    following :

  - /builddir/build/SOURCES/dlopen.sh
    ./nss_ldap-253/nss_ldap.so dlopen() of
    '././nss_ldap-253/nss_ldap.so' failed:
    ./././nss_ldap-253/nss_ldap.so: undefined symbol:
    request_key error: Bad exit status from
    /var/tmp/rpm-tmp.62652 (%build)

The missing libraries have been added, which resolves this issue.

When recursively enumerating the set of members in a given group, the
module would allocate insufficient space for storing the set of member
names if the group itself contained other groups, thus corrupting the
heap. This update includes a backported fix for this bug."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0805&L=scientific-linux-errata&T=0&P=1350
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f47f5ebe"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss_ldap package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
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
if (rpm_check(release:"SL5", reference:"nss_ldap-253-12.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
