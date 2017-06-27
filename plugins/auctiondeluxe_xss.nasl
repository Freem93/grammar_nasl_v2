#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11365);
 script_bugtraq_id(4069);
 script_cve_id("CVE-2002-0257");
 script_xref(name:"OSVDB", value:"9286");
 script_version ("$Revision: 1.29 $");

 script_name(english:"Auction Deluxe auction.pl Multiple Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The remote Auction Deluxe server is vulnerable to a cross-site
scripting attack. 

As a result, a user could easily steal the cookies of your legitimate
users and impersonate them." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Auction Deluxe 3.30 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/02/09");
 script_cvs_date("$Date: 2015/01/13 06:57:50 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for auction.pl";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl", "no404.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, no_xss: 1);

test_cgi_xss( port: port, cgi: "/auction.pl", 
	      qs: "searchstring=<script>foo</script>",
	      pass_str: "<script>foo</script>" );
