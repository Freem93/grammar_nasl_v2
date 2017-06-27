#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0107.
#

include("compat.inc");

if (description)
{
  script_id(85148);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2014-0015", "CVE-2014-0138", "CVE-2014-3613", "CVE-2014-3707", "CVE-2014-8150", "CVE-2015-3143", "CVE-2015-3148");
  script_bugtraq_id(65270, 66457, 69748, 70988, 71964, 74299, 74301);
  script_osvdb_id(102715, 104972, 111287, 114163, 116807, 121128, 121129);

  script_name(english:"OracleVM 3.3 : curl (OVMSA-2015-0107)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - require credentials to match for NTLM re-use
    (CVE-2015-3143)

  - close Negotiate connections when done (CVE-2015-3148)

  - reject CRLFs in URLs passed to proxy (CVE-2014-8150)

  - use only full matches for hosts used as IP address in
    cookies (CVE-2014-3613)

  - fix handling of CURLOPT_COPYPOSTFIELDS in
    curl_easy_duphandle (CVE-2014-3707)

  - fix manpage typos found using aspell (#1011101)

  - fix comments about loading CA certs with NSS in man
    pages (#1011083)

  - fix handling of DNS cache timeout while a transfer is in
    progress (#835898)

  - eliminate unnecessary inotify events on upload via file
    protocol (#883002)

  - use correct socket type in the examples (#997185)

  - do not crash if MD5 fingerprint is not provided by
    libssh2 (#1008178)

  - fix SIGSEGV of curl --retry when network is down
    (#1009455)

  - allow to use TLS 1.1 and TLS 1.2 (#1012136)

  - docs: update the links to cipher-suites supported by NSS
    (#1104160)

  - allow to use ECC ciphers if NSS implements them
    (#1058767)

  - make curl --trace-time print correct time (#1120196)

  - let tool call PR_Cleanup on exit if NSPR is used
    (#1146528)

  - ignore CURLOPT_FORBID_REUSE during NTLM HTTP auth
    (#1154747)

  - allow to enable/disable new AES cipher-suites (#1156422)

  - include response headers added by proxy in
    CURLINFO_HEADER_SIZE (#1161163)

  - disable libcurl-level downgrade to SSLv3 (#1154059)

  - do not force connection close after failed HEAD request
    (#1168137)

  - fix occasional SIGSEGV during SSL handshake (#1168668)

  - fix a connection failure when FTPS handle is reused
    (#1154663)

  - fix re-use of wrong HTTP NTLM connection (CVE-2014-0015)

  - fix connection re-use when using different log-in
    credentials (CVE-2014-0138)

  - fix authentication failure when server offers multiple
    auth options (#799557)

  - refresh expired cookie in test172 from upstream
    test-suite (#1069271)

  - fix a memory leak caused by write after close (#1078562)

  - nss: implement non-blocking SSL handshake (#1083742)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2015-July/000355.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected curl / libcurl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libcurl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"curl-7.19.7-46.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"libcurl-7.19.7-46.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / libcurl");
}
