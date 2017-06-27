#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1254 and 
# Oracle Linux Security Advisory ELSA-2015-1254 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85096);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/12/04 14:37:59 $");

  script_cve_id("CVE-2014-3613", "CVE-2014-3707", "CVE-2014-8150", "CVE-2015-3143", "CVE-2015-3148");
  script_bugtraq_id(69748, 70988, 71964, 74299, 74301);
  script_osvdb_id(111287, 114163, 116807, 121128, 121129);
  script_xref(name:"RHSA", value:"2015:1254");

  script_name(english:"Oracle Linux 6 : curl (ELSA-2015-1254)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1254 :

Updated curl packages that fix multiple security issues, several bugs,
and add two enhancements are now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The curl packages provide the libcurl library and the curl utility for
downloading files from servers using various protocols, including
HTTP, FTP, and LDAP.

It was found that the libcurl library did not correctly handle partial
literal IP addresses when parsing received HTTP cookies. An attacker
able to trick a user into connecting to a malicious server could use
this flaw to set the user's cookie to a crafted domain, making other
cookie-related issues easier to exploit. (CVE-2014-3613)

A flaw was found in the way the libcurl library performed the
duplication of connection handles. If an application set the
CURLOPT_COPYPOSTFIELDS option for a handle, using the handle's
duplicate could cause the application to crash or disclose a portion
of its memory. (CVE-2014-3707)

It was discovered that the libcurl library failed to properly handle
URLs with embedded end-of-line characters. An attacker able to make an
application using libcurl to access a specially crafted URL via an
HTTP proxy could use this flaw to inject additional headers to the
request or construct additional requests. (CVE-2014-8150)

It was discovered that libcurl implemented aspects of the NTLM and
Negotiate authentication incorrectly. If an application uses libcurl
and the affected mechanisms in a specific way, certain requests to a
previously NTLM-authenticated server could appears as sent by the
wrong authenticated user. Additionally, the initial set of credentials
for HTTP Negotiate-authenticated requests could be reused in
subsequent requests, although a different set of credentials was
specified. (CVE-2015-3143, CVE-2015-3148)

Red Hat would like to thank the cURL project for reporting these
issues.

Bug fixes :

* An out-of-protocol fallback to SSL version 3.0 (SSLv3.0) was
available with libcurl. Attackers could abuse the fallback to force
downgrade of the SSL version. The fallback has been removed from
libcurl. Users requiring this functionality can explicitly enable
SSLv3.0 through the libcurl API. (BZ#1154059)

* A single upload transfer through the FILE protocol opened the
destination file twice. If the inotify kernel subsystem monitored the
file, two events were produced unnecessarily. The file is now opened
only once per upload. (BZ#883002)

* Utilities using libcurl for SCP/SFTP transfers could terminate
unexpectedly when the system was running in FIPS mode. (BZ#1008178)

* Using the '--retry' option with the curl utility could cause curl to
terminate unexpectedly with a segmentation fault. Now, adding
'--retry' no longer causes curl to crash. (BZ#1009455)

* The 'curl --trace-time' command did not use the correct local time
when printing timestamps. Now, 'curl --trace-time' works as expected.
(BZ#1120196)

* The valgrind utility could report dynamically allocated memory leaks
on curl exit. Now, curl performs a global shutdown of the NetScape
Portable Runtime (NSPR) library on exit, and valgrind no longer
reports the memory leaks. (BZ#1146528)

* Previously, libcurl returned an incorrect value of the
CURLINFO_HEADER_SIZE field when a proxy server appended its own
headers to the HTTP response. Now, the returned value is valid.
(BZ#1161163)

Enhancements :

* The '--tlsv1.0', '--tlsv1.1', and '--tlsv1.2' options are available
for specifying the minor version of the TLS protocol to be negotiated
by NSS. The '--tlsv1' option now negotiates the highest version of the
TLS protocol supported by both the client and the server. (BZ#1012136)

* It is now possible to explicitly enable or disable the ECC and the
new AES cipher suites to be used for TLS. (BZ#1058767, BZ#1156422)

All curl users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-July/005229.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"curl-7.19.7-46.el6")) flag++;
if (rpm_check(release:"EL6", reference:"libcurl-7.19.7-46.el6")) flag++;
if (rpm_check(release:"EL6", reference:"libcurl-devel-7.19.7-46.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / libcurl / libcurl-devel");
}
