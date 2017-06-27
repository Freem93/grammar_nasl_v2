#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87322);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/24 13:12:23 $");

  script_cve_id(
    "CVE-2014-3566", 
    "CVE-2015-0204", 
    "CVE-2015-0235"
  );
  script_bugtraq_id(
    70574, 
    71936,
    72325
  );
  script_osvdb_id(
    113251,
    116794,
    117579
  );
  script_xref(name:"CERT", value:"243585");
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"CERT", value:"967332");
  
  script_name(english:"Xerox ColorQube 92XX Multiple OpenSSL Vulnerabilities (XRX15AD) (FREAK) (GHOST) (POODLE)");
  script_summary(english:"Checks system software version of Xerox ColorQube devices.");

  script_set_attribute(attribute:"synopsis", value:
"The remote multi-function device is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its model number and software version, the remote Xerox
ColorQube device is affected by multiple OpenSSL vulnerabilities :

  - A man-in-the-middle (MitM) information disclosure
    vulnerability, known as POODLE, exists due to the way
    SSL 3.0 handles padding bytes when decrypting messages
    encrypted using block ciphers in cipher block chaining
    (CBC) mode. A MitM attacker can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections.
    (CVE-2014-3566)

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists due to the
    support of weak EXPORT_RSA cipher suites with keys less
    than or equal to 512 bits. A man-in-the-middle attacker
    may be able to downgrade the SSL/TLS connection to use
    EXPORT_RSA cipher suites which can be factored in a
    short amount of time, allowing the attacker to intercept
    and decrypt the traffic. (CVE-2015-0204)

  - A heap-based buffer overflow condition exists in the GNU
    C Library (glibc) due to improper validation of
    user-supplied input to the glibc functions
    __nss_hostname_digits_dots(), gethostbyname(), and
    gethostbyname2(). This allows a remote attacker to cause
    a buffer overflow, resulting in a denial of service
    condition or the execution of arbitrary code. This
    vulnerability is known as GHOST. (CVE-2015-0235)");
  # https://www.xerox.com/download/security/security-bulletin/27a16-51ca83a45a218/cert_Security_Mini-_Bulletin_XRX15AD_for_CQ92xx_v1-0a.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7240b740");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate cumulative update as described in the Xerox
security bulletin in the referenced URL.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:colorqube");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("xerox_colorqube_detect.nbin");
  script_require_keys("www/xerox_colorqube", "www/xerox_colorqube/model", "www/xerox_colorqube/ssw");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Get model and system software version
model = get_kb_item_or_exit("www/xerox_colorqube/model");
ver = get_kb_item_or_exit("www/xerox_colorqube/ssw");

# 92XX only affected
if (model !~ "^92[0-9][0-9]$")
  audit(AUDIT_HOST_NOT, "an affected Xerox ColorQube model");

if (ver =~ "^[0-9]+\.050\.")
{
  # CBC
  fix = "061.050.225.18900";
}
else if (ver =~ "^[0-9]+\.080\.")
{
  # SBC
  fix = "061.080.225.18900";
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "Xerox ColorQube " + model + " System SW", ver);

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, "Xerox ColorQube " + model + " System SW", ver);

if (report_verbosity > 0)
{
  report =
    '\n  Model                             : Xerox ColorQube ' + model +
    '\n  Installed system software version : ' + ver +
    '\n  Fixed system software version     : ' + fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
