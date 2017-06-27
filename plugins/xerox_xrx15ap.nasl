#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87325);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/14 14:34:37 $");

  script_cve_id("CVE-2015-0204");
  script_bugtraq_id(71936);
  script_osvdb_id(116794);
  script_xref(name:"CERT", value:"243585");
  
  script_name(english:"Xerox WorkCentre 6400 OpenSSL RSA Temporary Key Handling EXPORT_RSA Ciphers Downgrade MitM (XRX15AP) (FREAK)");
  script_summary(english:"Checks system software version of Xerox WorkCentre devices.");

  script_set_attribute(attribute:"synopsis", value:
"The remote multi-function device is affected by a man-in-the-middle
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its model number and software version, the remote Xerox
WorkCentre 6400 device is affected by a security feature bypass
vulnerability, known as FREAK (Factoring attack on RSA-EXPORT Keys),
due to the support of weak EXPORT_RSA cipher suites with keys less
than or equal to 512 bits. A man-in-the-middle attacker may be able to
downgrade the SSL/TLS connection to use EXPORT_RSA cipher suites which
can be factored in a short amount of time, allowing the attacker to
intercept and decrypt the traffic.");
  # https://www.xerox.com/download/security/security-bulletin/2e28e-523433d609b1d/cert_Security_Mini-_Bulletin_XRX15AP_for_WC6400_v1-0.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff70a70b");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate cumulative update as described in the Xerox
security bulletin in the referenced URL.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

if (model =~ "^6400$")
  fix = "061.070.105.25200";
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
