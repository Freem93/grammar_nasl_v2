#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61343);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_name(english:"Scientific Linux Security Update : nss, nss-util, and nspr on SL6.x i386/x86_64");
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
"Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

It was found that a Certificate Authority (CA) issued a subordinate CA
certificate to its customer, that could be used to issue certificates
for any name. This update renders the subordinate CA certificate as
untrusted.

Note: This fix only applies to applications using the NSS Builtin
Object Token. It does not render the certificates untrusted for
applications that use the NSS library, but do not use the NSS Builtin
Object Token.

The nspr package has been upgraded to upstream version 4.9, which
provides a number of bug fixes and enhancements over the previous
version.

The nss-util package has been upgraded to upstream version 3.13.3,
which provides a number of bug fixes and enhancements over the
previous version.

The nss package has been upgraded to upstream version 3.13.3, which
provides numerous bug fixes and enhancements over the previous
version. In particular, SSL 2.0 is now disabled by default, support
for SHA-224 has been added, PORT_ErrorToString and PORT_ErrorToName
now return the error message and symbolic name of an NSS error code,
and NSS_GetVersion now returns the NSS version string.

These updated nss, nss-util, and nspr packages also provide fixes for
the following bugs :

  - A PEM module internal function did not clean up memory
    when detecting a non-existent file name. Consequently,
    memory leaks in client code occurred. The code has been
    improved to deallocate such temporary objects and as a
    result the reported memory leakage is gone.

  - Recent changes to NSS re-introduced a problem where
    applications could not use multiple SSL client
    certificates in the same process. Therefore, any attempt
    to run commands that worked with multiple SSL client
    certificates, such as the 'yum repolist' command,
    resulted in a re-negotiation handshake failure. With
    this update, a revised patch correcting this problem has
    been applied to NSS, and using multiple SSL client
    certificates in the same process is now possible again.

  - The PEM module did not fully initialize newly
    constructed objects with function pointers set to NULL.
    Consequently, a segmentation violation in libcurl was
    sometimes experienced while accessing a package
    repository. With this update, the code has been changed
    to fully initialize newly allocated objects. As a
    result, updates can now be installed without problems.

  - A lack-of-robustness flaw caused some administration
    servers to terminate unexpectedly because the mod_nss
    module made nss calls before initializing nss as per the
    documented API. With this update, nss protects itself
    against being called before it has been properly
    initialized by the caller.

  - Compilation errors occurred with some compilers when
    compiling code against NSS 3.13.1. The following error
    message was displayed :

pkcs11n.h:365:26: warning: '__GNUC_MINOR' is not defined

An upstream patch has been applied to improve the code and the problem
no longer occurs.

  - Unexpected terminations were reported in the messaging
    daemon (qpidd) included in Red Hat Enterprise MRG after
    a recent update to nss. This occurred because qpidd made
    nss calls before initializing nss. These updated
    packages prevent qpidd and other affected processes that
    call nss without initializing as mandated by the API
    from crashing.

Users of NSS, NSPR, and nss-util are advised to upgrade to these
updated packages, which fix these issues and add these enhancements.
After installing this update, applications using NSS, NSPR, or
nss-util must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=1661
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36c5f7d1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
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
if (rpm_check(release:"SL6", reference:"nspr-4.9-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-debuginfo-4.9-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-devel-4.9-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-3.13.3-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-debuginfo-3.13.3-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-devel-3.13.3-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-pkcs11-devel-3.13.3-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-sysinit-3.13.3-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-tools-3.13.3-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-3.13.3-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-debuginfo-3.13.3-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-devel-3.13.3-2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
