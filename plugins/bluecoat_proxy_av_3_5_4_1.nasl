#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93410);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2015-3194", "CVE-2015-3195");
  script_bugtraq_id(78623, 78626);
  script_osvdb_id(131038, 131039);
  script_xref(name:"IAVA", value:"2016-A-0229");

  script_name(english:"Blue Coat ProxyAV 3.5.x < 3.5.4.1 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of Blue Coat ProxyAV.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Blue Coat ProxyAV
firmware installed on the remote device is 3.5.x prior to 3.5.4.1. It
is, therefore, affected by the following vulnerabilities in the
bundled version of OpenSSL :

  - A NULL pointer dereference flaw exists in file
    rsa_ameth.c due to improper handling of ASN.1 signatures
    that are missing the PSS parameter. A remote attacker
    can exploit this to cause the signature verification
    routine to crash, resulting in a denial of service
    condition. (CVE-2015-3194)

  - A flaw exists in the ASN1_TFLG_COMBINE implementation in
    file tasn_dec.c related to handling malformed
    X509_ATTRIBUTE structures. A remote attacker can exploit
    this to cause a memory leak by triggering a decoding
    failure in a PKCS#7 or CMS application, resulting in a
    denial of service. (CVE-2015-3195)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://bto.bluecoat.com/security-advisory/sa105");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Blue Coat ProxyAV version 3.5.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:bluecoat:proxyav");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("bluecoat_proxy_av_version.nasl");
  script_require_keys("www/bluecoat_proxyav");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");

port = get_kb_item_or_exit("www/bluecoat_proxyav");
ver = get_kb_item_or_exit("www/bluecoat_proxyav/" + port + "/version");

url = build_url(port:port, qs:"/");

if (ver !~ "^3\.5\.")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Blue Coat ProxyAV", url, ver);

fix = "3.5.4.1";

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 3.5.4.1' +
    '\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Blue Coat ProxyAV", url, ver);
