#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14715);
  script_version("$Revision: 1.11 $"); 
  script_cvs_date("$Date: 2011/11/28 21:39:46 $");

  script_cve_id("CVE-2004-0004");
  script_bugtraq_id(9435);
  script_osvdb_id(3615);

  script_name(english:"OpenCA crypto-utils.lib libCheckSignature Function Signature Validation Weakness");
  script_summary(english:"Checks for the version of OpenCA");

  script_set_attribute(attribute:"synopsis", value:
"A remote application is vulnerable to signature verification bypass.");
  script_set_attribute(attribute:"description", value:
"The remote host seems to be running an older version of OpenCA. 

It is reported that OpenCA versions up to and incluing 0.9.1.6 contains 
a flaw that may lead an attacker to bypass signature verification of a 
certificate.");
  script_set_attribute(attribute:"solution", value:"Upgrade to the newest version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/16");

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

if ( egrep(pattern:"^0\.([0-8]\.|9\.(0|1$|1\.[1-6][^0-9]))", string:version) ) security_hole(port);

