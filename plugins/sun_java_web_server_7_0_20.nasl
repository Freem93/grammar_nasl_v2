#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76593);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/08/08 04:47:46 $");

  script_cve_id(
    "CVE-2013-1739",
    "CVE-2013-1740",
    "CVE-2013-1741",
    "CVE-2013-5605",
    "CVE-2013-5606",
    "CVE-2014-1490",
    "CVE-2014-1491",
    "CVE-2014-1492"
  );
  script_bugtraq_id(
    62966,
    63736,
    63737,
    63738,
    64944,
    65332,
    65335,
    66356
  );
  script_osvdb_id(
    98402,
    99746,
    99747,
    99748,
    102170,
    102876,
    102877,
    104708
  );

  script_name(english:"Oracle iPlanet Web Server 7.0.x < 7.0.20 Multiple Vulnerabilities");
  script_summary(english:"Checks the version in the admin console.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle iPlanet Web Server
(formerly Sun Java System Web Server) running on the remote host is
7.0.x prior to 7.0.20. It is, therefore, affected by the following
vulnerabilities in the Network Security Services (NSS) :

  - The implementation of NSS does not ensure that data
    structures are initialized, which can result in a denial
    of service or disclosure of sensitive information.
    (CVE-2013-1739)

  - An error exists in the ssl_Do1stHandshake() function in
    file sslsecur.c due to unencrypted data being returned
    from PR_Recv when the TLS False Start feature is
    enabled. A man-in-the-middle attacker can exploit this,
    by using an arbitrary X.509 certificate, to spoof SSL
    servers during certain handshake traffic.
    (CVE-2013-1740)

  - An integer overflow condition exists related to handling
    input greater than half the maximum size of the
    'PRUint32' value. A remote attacker can exploit this to
    cause a denial of service or possibly have other impact.
    (CVE-2013-1741)

  - An error exists in the Null_Cipher() function in the
    file ssl3con.c related to handling invalid handshake
    packets. A remote attacker, using a crafted request, can
    exploit this to execute arbitrary code. (CVE-2013-5605)

  - An error exists in the CERT_VerifyCert() function in the
    file certvfy.c when handling trusted certificates with
    incompatible key usages. A remote attacker, using a
    crafted request, can exploit this to have an invalid
    certificates treated as valid. (CVE-2013-5606)

  - A race condition exists in libssl that occurs during
    session ticket processing. A remote attacker can exploit
    this to cause a denial of service. (CVE-2014-1490)

  - Network Security Services (NSS) does not properly
    restrict public values in Diffie-Hellman key exchanges,
    allowing a remote attacker to bypass cryptographic
    protection mechanisms. (CVE-2014-1491)

  - An issue exists in the Network Security (NSS) library
    due to improper handling of IDNA domain prefixes for
    wildcard certificates. A man-in-the-middle attacker,
    using a crafted certificate, can exploit this to spoof
    an SSL server. (CVE-2014-1492)");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52cfd1ae");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle iPlanet Web Server 7.0.20 or later.

Note that, at the time of this writing, there is no patch available
for installations on Microsoft Windows hosts. Please contact the
vendor regarding availability dates for the patch for iPlanet 7.0
(patch #145847).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:iplanet_web_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:network_security_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_iplanet_web_server_detect.nbin");
  script_require_keys("installed_sw/Oracle iPlanet Web Server/");
  
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

app_name = "Oracle iPlanet Web Server";
port = get_http_port(default:8989);

install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];

fix = "7.0.20";
min = "7.0";

if (
  ver_compare(ver:version, fix:min, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + app_name +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 7.0.20' +
        '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
