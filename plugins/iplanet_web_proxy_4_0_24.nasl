#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76592);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/02/04 22:38:29 $");

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

  script_name(english:"Oracle iPlanet Web Proxy Server 4.0 < 4.0.24 Multiple Vulnerabilities");
  script_summary(english:"Checks proxyd.exe's product version.");

  script_set_attribute(attribute:"synopsis", value:
"A web proxy server on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Oracle iPlanet Web Proxy Server
(formerly Sun Java System Web Proxy Server) 4.0 prior to 4.0.24. It
is, therefore, affected by the following vulnerabilities :

  - The implementation of Network Security Services (NSS)
    does not ensure that data structures are initialized,
    which could result in a denial of service or disclosure
    of sensitive information. (CVE-2013-1739)

  - The implementation of Network Security Services (NSS)
    does not properly handle the TLS False Start feature
    and could allow man-in-the-middle attacks.
    (CVE-2013-1740)

  - An error exists related to handling input greater than
    half the maximum size of the 'PRUint32' value.
    (CVE-2013-1741)

  - An error exists in the 'Null_Cipher' function in the
    file 'ssl/ssl3con.c' related to handling invalid
    handshake packets that could allow arbitrary code
    execution. (CVE-2013-5605)

  - An error exists in the 'CERT_VerifyCert' function in
    the file 'lib/certhigh/certvfy.c' that could allow
    invalid certificates to be treated as valid.
    (CVE-2013-5606)

  - Network Security Services (NSS) contains a race
    condition in libssl that occurs during session ticket 
    processing. A remote attacker can exploit this flaw
    to cause a denial of service. (CVE-2014-1490)

  - Network Security Services (NSS) does not properly
    restrict public values in Diffie-Hellman key exchanges,
    allowing a remote attacker to bypass cryptographic
    protection mechanisms. (CVE-2014-1491)

  - An issue exists in the Network Security (NSS) library
    due to improper handling of IDNA domain prefixes for
    wildcard certificates. This issue could allow man-in-
    the-middle attacks. (CVE-2014-1492)");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52cfd1ae");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.0.24 or later.

Note that, in the case of installs on Microsoft Windows hosts, at the
time of this writing there is no patch available for Microsoft Windows
hosts. Please contact the vendor regarding availability dates for the
patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:iplanet_web_proxy_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("iplanet_web_proxy_installed.nbin");
  script_require_keys("SMB/iplanet_web_proxy_server/path", "SMB/iplanet_web_proxy_server/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = 'Oracle iPlanet Web Proxy Server';
get_install_count(app_name:app_name, exit_if_zero:TRUE);
fix = NULL;

# Only 1 install of the server is possible.
install = get_installs(app_name:app_name);
if (install[0] == IF_NOT_FOUND) audit(AUDIT_NOT_INST, app_name);
install = install[1][0];

version = install['version'];
path = install['path'];

fixed_version = '4.0.24';
min_version = '4.0';

if (
  ver_compare(ver:version, fix:min_version, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version;

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
