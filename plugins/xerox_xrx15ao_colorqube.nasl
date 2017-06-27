#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86710);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id(
    "CVE-2014-0076", 
    "CVE-2014-0221", 
    "CVE-2014-0224", 
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    66363,
    67898,
    67899,
    67901
  );
  script_osvdb_id(
    104810,
    107729,
    107731,
    107732,
    129429
  );
  script_xref(name:"CERT", value:"978508");
  
  script_name(english:"Xerox ColorQube 8570 / 8870 Multiple Vulnerabilities (XRX15OA)");
  script_summary(english:"Checks system software version of Xerox ColorQube devices.");

  script_set_attribute(attribute:"synopsis", value:
"The remote multi-function device is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its model number and software version, the remote host is
a Xerox ColorQube device that is affected by multiple
vulnerabilities :

  - An information disclosure vulnerability exists in the
    bundled version of OpenSSL due to a flaw in the
    implementation of the Elliptic Curve Digital Signature
    Algorithm (ECDSA) that allows nonce disclosure via the
    'FLUSH+RELOAD' cache side-channel attack.
    (CVE-2014-0076)

  - A denial of service vulnerability exists in the bundled
    version of OpenSSL due to a recursion flaw in the DTLS
    functionality. A remote attacker can exploit this, via a
    specially crafted request, to crash the DTLS client
    application. (CVE-2014-0221)

  - An unspecified error exists in the bundled version of
    OpenSSL due to a flaw in the handshake process. A remote
    attacker can exploit this, via a crafted handshake, to
    force the client or server to use weak keying material,
    allowing simplified man-in-the-middle attacks.
    (CVE-2014-0224)

  - A denial of service vulnerability exists in the bundled
    version of OpenSSL due to an unspecified flaw related to
    the ECDH ciphersuite. Note this issue only affects
    OpenSSL TLS clients. (CVE-2014-3470)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input. A remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (VulnDB 129429)");
  # https://www.xerox.com/download/security/security-bulletin/33a01-5228bdf5d027e/cert_Security_Mini-_Bulletin_XRX15AO_for_CQ8570-CQ8870_v1-0.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15fd6bad");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"see_also", value:"http://ccsinjection.lepidum.co.jp/");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/06/05/earlyccs.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to firmware version PS 4.76.0 and net controller version
43.90.10.14.2015.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:colorqube");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("xerox_colorqube_detect.nbin");
  script_require_keys("www/xerox_colorqube", "www/xerox_colorqube/model", "www/xerox_colorqube/ess",
      "www/xerox_colorqube/ps");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Get model and system software version
model = get_kb_item_or_exit("www/xerox_colorqube/model");
ess = get_kb_item("www/xerox_colorqube/ess");
ps = get_kb_item("www/xerox_colorqube/ps");

# ColorQube 8570/8870
if ( model !~ "^8[58]70([^0-9]|$)")
  audit(AUDIT_HOST_NOT, "an affected Xerox ColorQube model");

ess_fix = "43.90.10.14.2015";
ps_fix = "4.76.0";

vuln = FALSE;

if (ess)
{
  if (ver_compare(ver:ess, fix:ess_fix, strict:FALSE) < 0)
    vuln = TRUE;
}
else
  ess = "unknown"; # not including install_func just to get UNKNOWN_VER

if (ps)
{
  if (ver_compare(ver:ps, fix:ps_fix, strict:FALSE) < 0)
    vuln = TRUE;
}
else
  ps = "unknown"; # not including install_func just to get UNKNOWN_VER

if (vuln)
{
  set_kb_item(name:'www/0/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Xerox ColorQube model            : ' + model +
      '\n  Installed net controller version : ' + ess +
      '\n  Fixed net controller version     : ' + ess_fix +
      '\n  Installed firmware version       : ' + ps +
      '\n  Fixed firmware version           : ' + ps_fix;

    security_hole(port:0, extra:report);
  }
  else
    security_hole(0);
}
else
  audit(AUDIT_HOST_NOT, "affected");
