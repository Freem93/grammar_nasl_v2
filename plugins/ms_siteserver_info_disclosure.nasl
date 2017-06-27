#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID


include("compat.inc");

if (description)
{
 script_id(11018);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2014/04/25 20:39:19 $");

 script_cve_id("CVE-2002-1769");
 script_bugtraq_id(3998);
 script_osvdb_id(
  831,
  17652,
  17653,
  17654,
  17655,
  17656,
  17657,
  17658,
  17659,
  17660,
  17661,
  17662,
  17663,
  17664,
  17665,
  17666,
  17667,
  17668,
  17669,
  17670,
  17671
 );

 script_name(english:"Microsoft Site Server Multiple Script Information Disclosure");
 script_summary(english:"Determine if the remote host is vulnerable to a disclosure vuln.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server seems to leak information when some pages are
accessed using the account 'LDAP_AnonymousUser' with the password
'LdapPassword_1'.

Pages which leak information include, but are not limited to :

  - /SiteServer/Admin/knowledge/persmbr/vs.asp
  - /SiteServer/Admin/knowledge/persmbr/VsTmPr.asp
  - /SiteServer/Admin/knowledge/persmbr/VsLsLpRd.asp
  - /SiteServer/Admin/knowledge/persmbr/VsPrAuoEd.asp");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=kb;EN-US;248840");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=vulnwatch&m=101235440104716&w=2");
 script_set_attribute(attribute:"solution", value:
"Install SP4 for Site Server 3.0.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/08");
 script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/30");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP");
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


function make_request(port, file)
{
  local_var r, w;

  w = http_send_recv3(method:"GET", item: file, port: port,
    username: SCRIPT_NAME, password: unixtime());
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  if (w[0] =~ "^HTTP/[0-9]\.[0-9] 200 ")
    exit(0, "Resource "+file+" is not protected on port "+port);

  w = http_send_recv3(method:"GET", item: file, port: port,
    username: "LDAP_Anonymous", password: "LdapPassword_1");
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");

  if (w[0] =~ "^HTTP/[0-9]\.[0-9] 200 ")
  {
    if(get_kb_item(string("www/no404/", port)))
     {
     if("Microsoft" >< r){
      	security_warning(port);
	exit(0);
     }
    }
    else {
      	security_warning(port);
	exit(0);
    }
  }
}
port = get_http_port(default:80);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if ( get_kb_item("www/no404/" + port) ) exit(0, "the web server on port "+port+" does not return 404 codes");

if( can_host_asp(port:port) )
{
 make_request(port:port, file:"/SiteServer/Admin/knowledge/persmbr/vs.asp");
 make_request(port:port, file:"/SiteServer/Admin/knowledge/persmbr/VsTmPr.asp");
 make_request(port:port, file:"/SiteServer/Admin/knowledge/persmbr/VsLsLpRd.asp");
 make_request(port:port, file:"/SiteServer/Admin/knowledge/persmbr/VsPrAuoEd.asp");
}
