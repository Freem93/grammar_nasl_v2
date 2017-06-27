#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(15935);
  script_version("$Revision: 1.13 $");
  script_cve_id("CVE-2004-2500");
  script_bugtraq_id(11872);
  script_osvdb_id(12292);

  script_name(english:"IlohaMail < 0.8.14RC1 Unspecified Vulnerability");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an unspecified vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running at least one instance of IlohaMail version
0.8.13 or earlier.  Such versions are reportedly affected by an
unspecified vulnerability." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?group_id=54027&release_id=288409" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IlohaMail version 0.8.14RC1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/09");
 script_cvs_date("$Date: 2011/03/17 01:57:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks IlohaMail version");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_list("www/" + port + "/ilohamail");
if (isnull( kb )) exit(0);


foreach item (kb) 
{
  matches = eregmatch(string:item, pattern:"^(.+) under (.*)$");
  if ( ereg(pattern:"^0\.([0-7]\.|8\.([0-9][^0-9]|1[0-3]))", string:matches[1]) )
	{
	security_hole(port);
	exit(0);
	}
}
