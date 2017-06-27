#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77438);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/15 04:35:15 $");

  script_cve_id(
    "CVE-2014-0076",
    "CVE-2014-0098",
    "CVE-2014-0963",
    "CVE-2014-0965",
    "CVE-2014-3022",
    "CVE-2014-3070",
    "CVE-2014-3083",
    "CVE-2014-4244",
    "CVE-2014-4263",
    "CVE-2014-4764",
    "CVE-2014-4767"
  );
  script_bugtraq_id(
    66303,
    66363,
    67238,
    68210,
    68211,
    68624,
    68636,
    69296,
    69297,
    69298,
    69301
  );
  script_osvdb_id(
    104580,
    104810,
    106786,
    108454,
    108455,
    109141,
    109142,
    110185,
    110186,
    110187,
    110188
  );

  script_name(english:"IBM WebSphere Application Server 8.5 < Fix Pack 8.5.5.3 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server may be affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running IBM WebSphere Application Server
8.5 prior to Fix Pack 8.5.5.3. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in the Elliptic Curve Digital Signature
    Algorithm implementation which could allow a malicious
    process to recover ECDSA nonces.
    (CVE-2014-0076, PI19700)

  - A denial of service flaw exists in the 'mod_log_config'
    when logging a cookie with an unassigned value. A remote
    attacker, using a specially crafted request, can cause
    the program to crash. (CVE-2014-0098, PI13028)

  - A denial of service flaw exists within the IBM Security
    Access Manager for Web with the Reverse Proxy component.
    This could allow a remote attacker, using specially
    crafted TLS traffic, to cause the application on the
    system to become unresponsive. (CVE-2014-0963, PI17025)

  - An information disclosure flaw exists when handling SOAP
    responses. This could allow a remote attacker to
    potentially gain access to sensitive information.
    (CVE-2014-0965, PI11434)

  - An information disclosure flaw exists. A remote
    attacker, using a specially crafted URL, could gain
    access to potentially sensitive information.
    (CVE-2014-3022, PI09594)

  - A flaw exists within the 'addFileRegistryAccount'
    Virtual Member Manager SPI Admin Task, which creates
    improper accounts. This could allow a remote attacker
    to bypass security checks. (CVE-2014-3070, PI16765)

  - An unspecified information disclosure flaw exists. This
    could allow a remote attacker access to gain sensitive
    information. (CVE-2014-3083, PI17768)

  - An information disclosure flaw exists within the
    'share/classes/sun/security/rsa/RSACore.java' class
    related to 'RSA blinding' caused during operations using
    private keys and measuring timing differences. This
    could allow a remote attacker to gain information about
    used keys. (CVE-2014-4244)

  - A flaw exists within the 'validateDHPublicKey' function
    in the 'share/classes/sun/security/util/KeyUtil.java'
    class which is triggered during the validation of
    Diffie-Hellman public key parameters. This could allow a
    remote attacker to recover a key. (CVE-2014-4263)

  - A flaw exists within the Load Balancer for IPv4
    Dispatcher component. This could allow a remote attacker
    to crash the Load Balancer. (CVE-2014-4764, PI21189)

  - A flaw exists within the Liberty Repository when
    installing features. This could allow an authenticated
    remote attacker to install and execute arbitrary code.
    (CVE-2014-4767, PI21284)");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_potential_security_vulnerabilities_fixed_in_ibm_websphere_application_server_8_5_5_3?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f6f4bc1");
  # Downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24038133");
  # Fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27036319#8553");
  # Sec bulletin
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21681249");
  # Java JDK items
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21680418");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 8.5.5.3 for version 8.5 (8.5.0.0) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880, embedded:0);

version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

if (version !~ "^8\.5([^0-9]|$)")
  audit(AUDIT_NOT_LISTEN, "IBM WebSphere Application Server 8.5", port);

if (version =~ "^[0-9]+(\.[0-9]+)?$")
  audit(AUDIT_VER_NOT_GRANULAR, "IBM WebSphere Application Server", port, version);

fixed = '8.5.5.3';

if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM WebSphere Application Server", port, version);
