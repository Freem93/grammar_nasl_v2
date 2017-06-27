#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45039);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2006-4343", "CVE-2008-1678", "CVE-2009-3245", "CVE-2009-3555", "CVE-2009-4355");
  script_bugtraq_id(31692, 36935, 38562);
  script_osvdb_id(29263, 47810, 59971, 61684, 62844);
  script_xref(name:"Secunia", value:"37291");
  script_xref(name:"Secunia", value:"38200");

  script_name(english:"OpenSSL < 0.9.8m Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server has multiple SSL-related vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server uses a version of
OpenSSL older than 0.9.8m.  Such versions have the following
vulnerabilities :

  - Session renegotiations are not handled properly, which could
    be exploited to insert arbitrary plaintext by a
    man-in-the-middle. (CVE-2009-3555)

  - The library does not check for a NULL return value from calls
    to the bn_wexpand() function, which has unspecified impact.
    (CVE-2009-3245)
   
  - A memory leak in the zlib_stateful_finish function in crypto/comp/c_zlib.c 
    allows remote attackers to cause a denial of service via vectors that 
    trigger incorrect calls to the CRYPTO_cleanup_all_ex_data function.
    (CVE-2008-1678, CVE-2009-4355)
    
    For this vulnerability to be exploitable, compression must be enabled in OpenSSL
    for SSL/TLS connections.    
"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rt.openssl.org/Ticket/Display.html?id=2111&user=guest&pass=guest"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=openssl-announce&m=126714485629486&w=2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8m or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 310, 399);
  script_set_attribute(attribute:"vuln_publication_date",value:"2009/11/09");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/02/25");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/11");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");


if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_http_port(default:80);
banner = get_backport_banner(banner:get_http_banner(port:port));
if (!banner) exit(1, "Unable to get the banner from web server on port "+port+".");

if (!egrep(string:banner, pattern:'^Server:'))
  exit(0, "The web server on port "+port+" doesn't return a Server response header.");
if ("OpenSSL/" >!< banner)
  exit(0, "The Server response header for the web server on port "+port+" doesn't mention OpenSSL.");

pat = "^Server:.*OpenSSL/([^ ]+)";
version = NULL;

foreach line (split(banner, sep:'\r\n', keep:FALSE))
{
  match = eregmatch(pattern:pat, string:line);
  if (!isnull(match))
  {
    version = match[1];
    break;
  }
}

if (isnull(version))
  exit(0, "Failed to extract the version of OpenSSL used by the web server on port "+port+".");

# anything less than 0.9.8m, and anything that looks like 0.9.8-beta
if (version =~ "^0\.9\.([0-7]|8([^a-z0-9]|[a-l]|$))")
{
  if (report_verbosity > 0)
  {
    report =
      '\nOpenSSL version '+version+' appears to be running on the remote\n'+
      'host based on the following Server response header :\n\n'+
      '  '+line+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'The web server on port "+port+" uses OpenSSL '+version+', which is not affected.');
