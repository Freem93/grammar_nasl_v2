#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14714);
  script_version("$Revision: 1.9 $"); 
  script_cvs_date("$Date: 2011/11/28 21:39:46 $");

  script_cve_id("CVE-2003-0960");
  script_bugtraq_id(9123);
  script_osvdb_id(2884);

  script_name(english:"OpenCA Multiple Signature Validation Bypass");
  script_summary(english:"Checks for the version of OpenCA");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is vulnerable to several flaws.");
  script_set_attribute(attribute:"description", value:
"The remote host seems to be running an older version of OpenCA. 

It is reported that OpenCA versions up to and incluing 0.9.1.3 contains 
multiple flaws that may allow revoked or expired certificates to be 
accepted as valid.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencie("openca_html_injection.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

version = get_kb_item("www/" + port + "/openca/version");
if ( ! version ) exit(0);


if ( egrep(pattern:"(0\.[0-8]\.|0\.9\.(0|1$|1\.[1-3][^0-9]))", string:version) ) security_hole(port);

