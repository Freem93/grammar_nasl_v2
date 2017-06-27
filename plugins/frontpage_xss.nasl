#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11395);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2017/01/27 15:06:51 $");

  script_cve_id("CVE-2000-0746");
  script_bugtraq_id(1594, 1595);
  script_osvdb_id(9199);
  script_xref(name:"MSFT", value:"MS00-060");

  script_name(english:"Microsoft IIS shtml.dll XSS");
  script_summary(english:"Checks for the presence of a FrontPage XSS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the FrontPage extensions running on the remote web
server is affected by a cross-site scripting (XSS) vulnerability in
shtml.dll due to improper validation of filenames. An unauthenticated,
remote attacker can exploit this, by convincing a user to follow a
specially crafted URL, to execute arbitrary script code in the user's
browser session.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms00-060");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for IIS 4.0 and 5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2000/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:internet_information_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (get_kb_item("www/" +port+ "/generic_xss"))
  exit(0, "The web server on port "+port+" is vulnerable to XSS.");

banner = get_http_banner(port:port);
if (isnull(banner))
  audit(AUDIT_WEB_BANNER_NOT, port);
if ("IIS" >!< banner)
  audit(AUDIT_WRONG_WEB_SERVER, port, "IIS");

# Verify page exists first
url = "/_vti_bin/shtml.dll";
xss_string = SCRIPT_NAME;
xss = "<script>alert("+'"'+xss_string+'"'+ ")</script>";

res = http_send_recv3(
  method : "GET",
  item   : url,
  port   : port,
  exit_on_fail : TRUE
);
if (res[0] !~ "^HTTP/[0-9\.]+ 200")
  audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);

res2 = http_send_recv3(
  method : "GET",
  item   : url + "/" + xss,
  port   : port,
  exit_on_fail : TRUE
);
if(
  (res2[0] =~ "^HTTP/[0-9\.]+ 200") &&
  (xss >< res2[2])
)
{
  output = strstr(res2[2], xss);
  if (empty_or_null(output)) output = res2[2];

  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    line_limit : 5,
    xss        : TRUE,
    request    : make_list(build_url(port:port, qs:url+"/"+xss)),
    output     : chomp(output)
  );
}
else
  audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
