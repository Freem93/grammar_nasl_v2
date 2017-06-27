#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87326);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id(
    "CVE-2015-0204",
    "CVE-2015-4000",
    "CVE-2015-3963"
  );
  script_bugtraq_id(
    71936,
    74733,
    75302
  );
  script_osvdb_id(
    116794,
    122331,
    123469
  );
  script_xref(name:"CERT", value:"243585");
  script_xref(name:"IAVB", value:"2015-B-0082");
  
  script_name(english:"Xerox WorkCentre 4260 / 4265 Multiple Vulnerabilities (XRX15AV) (FREAK) (Logjam)");
  script_summary(english:"Checks system software version of Xerox WorkCentre devices.");

  script_set_attribute(attribute:"synopsis", value:
"The remote multi-function device is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its model number and software version, the remote Xerox
WorkCentre 4260 / 4265 device is affected by multiple
vulnerabilities :

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists due to the
    support of weak EXPORT_RSA cipher suites with keys less
    than or equal to 512 bits. A man-in-the-middle attacker
    may be able to downgrade the SSL/TLS connection to use
    EXPORT_RSA cipher suites which can be factored in a
    short amount of time, allowing the attacker to intercept
    and decrypt the traffic. (CVE-2015-0204)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)

  - A TCP connection spoofing vulnerability exists due to
    weak TCP initial sequence number (ISN) generation. A
    man-in-the-middle attacker can exploit this to spoof TCP
    connections or cause a denial of service.
    (CVE-2015-3963)

Note that the FREAK (CVE-2015-0204) vulnerability on WorkCentre 4260
was fixed in a prior release.");
  # https://www.xerox.com/download/security/security-bulletin/1e9b7-5246c7996a40b/cert_Security_Mini-_Bulletin_XRX15AV_for_WC4260_WC4265_v1-02.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b2b309a");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"see_also", value:"http://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate cumulative update as described in the Xerox
security bulletin in the referenced URL.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (model =~ "^4260$")
  fix = "30.105.41.000";
else if (model =~ "^4265$")
  fix = "50.003.11.000";
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
