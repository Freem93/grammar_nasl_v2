#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87323);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/24 13:12:23 $");

  script_cve_id("CVE-2015-0204", "CVE-2014-3566");
  script_bugtraq_id(71936, 70574);
  script_osvdb_id(116794, 113251);
  script_xref(name:"CERT", value:"243585");
  
  script_name(english:"Xerox WorkCentre 3550 OpenSSL Multiple Vulnerabilities (XRX15AJ) (FREAK) (POODLE)");
  script_summary(english:"Checks system software version of Xerox WorkCentre devices.");

  script_set_attribute(attribute:"synopsis", value:
"The remote multi-function device is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its model number and software version, the remote Xerox
WorkCentre 3550 device is affected by multiple OpenSSL
vulnerabilities :

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
    and decrypt the traffic. (CVE-2015-0204)");
  # https://www.xerox.com/download/security/security-bulletin/30b1a-51f527aa71c0f/cert_Security_Mini-_Bulletin_XRX15AJ_for_WC3550_v1-0.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21539c55");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate cumulative update as described in the Xerox
security bulletin in the referenced URL.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("xerox_workcentre_detect.nasl");
  script_require_keys("www/xerox_workcentre", "www/xerox_workcentre/model", "www/xerox_workcentre/ssw");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Get model and system software version
model = get_kb_item_or_exit("www/xerox_workcentre/model");
ver = get_kb_item_or_exit("www/xerox_workcentre/ssw");

# 3550 only affected
if (model =~ "^3550$")
  fix = "25.003.33.000";
else
  audit(AUDIT_HOST_NOT, "an affected Xerox WebCentre model");

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, "Xerox WorkCentre " + model + " System SW", ver);

if (report_verbosity > 0)
{
  report =
    '\n  Model                             : Xerox WorkCentre ' + model +
    '\n  Installed system software version : ' + ver +
    '\n  Fixed system software version     : ' + fix + '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
