# Script to check for Apache Authentication Modules SQL Insertion Vulnerability
#
# This script is copyright (c) 2001 Matt Moore <matt@westpoint.ltd.uk> 
#
# modifications by rd : use of regexps 
# modifications by Tenable :
#   - Added description with Synopsis, See also, risk factor
#
# See the Nessus Scripts License for more details


include("compat.inc");

if(description)
{
 script_id(10752);
 script_bugtraq_id(3251, 3253);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2001-1379");
 script_xref(name:"OSVDB", value:"623");
 script_xref(name:"OSVDB", value:"9693");

 script_name(english:"Apache Auth Module SQL Injection");
 script_summary(english:"Checks for vulnerable Apache Auth modules");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a SQL query manipulation
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'mod_auth_pgsql_sys' module is prior to 0.9.6. It is, therefore,
affected by a SQL injection vulnerability that allows an attacker to
bypass authentication." );
 # https://web.archive.org/web/20020228224909/http://archives.neohapsis.com/archives/vulnwatch/2001-q3/0040.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e048929" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to mod_auth_pgsql_sys version 0.9.6 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/09/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/08/29");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2016 Matt Moore");
 
 family["english"] = "Web Servers";
 script_family(english:family["english"]);

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# Script code begins... 
#

include("http_func.inc");

 port = get_http_port(default:80);


 banner = get_http_banner(port: port);
 


  report = 
string("There is a vulnerable version of the NAME module installed on this\n",
"Apache Web Server.\n",
"This module is vulnerable to a SQL insertion attack that could allow an\n",
"attacker to execute arbitrary SQL statements.\n\n");

# Now check whether the banner contains references to the vulnerable modules...

  # Check for mod_auth_pg v1.2b
  if (egrep(pattern:"^Server:.*mod_auth_pg/((0\.[0-9])|(1\.[0-1])|1\.2b[0-2])([^0-9]|$)", string:banner))
  {
   r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)",
   			 replace:"\1mod_auth_pg\31.3\5http://authpg.sourceforge.net\7",
			 string:report);

   security_hole(port:port, extra:r);
   exit(0);
  }

# Check for mod_auth_mysql v1.9 
  
  if (egrep(pattern:"^Server:.*mod_auth_mysql/((0\.[0-9])|(1\.[0-9]))([^0-9]|$)", string:banner))
  {
   r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)",
   			 replace:"\1mod_auth_mysql\31.10\5ftp://ftp.kcilink.com/pub/\7",
			 string:report);

   security_hole(port:port, extra:r);
  }

# Check for mod_auth_oracle v0.5.1 
  if (egrep(pattern:"^Server:.*mod_auth_oracle/0\.([0-4].*|5\.[0-1]([^0-9]|$))", string:banner))
  {
    r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)",
   			 replace:"\1mod_auth_oracle\30.5.2\5some place\7",
			 string:report);
			 
			 
   security_hole(port:port, extra:r);
  }

# Check for mod_auth_pgsql v0.9.5 
  if (egrep(pattern:"^Server:.*mod_auth_pgsql/0\.(([0-8]\..*)|(9\.[0-5]([^0-9]|$))).*", string:banner))
  {
   r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)",
   			 replace:"\1mod_auth_pgsql\30.9.6\5http://www.giuseppetanzilli.it/mod_auth_pgsql/dist\7",
			 string:report);
			 

   security_hole(port:port, extra:r);
  }

# Check for mod_auth_pgsql_sys v0.9.4
 
  if (egrep(pattern:"^Server:.*mod_auth_pgsql_sys/0\.(([0-8]\..*)|(9\.[0-4]([^0-9]|$))).*", string:banner))
  {
   r = ereg_replace(pattern:"(.*)(NAME)(.*)(VERSION)(.*)(URL)(.*)",
   			 replace:"\1mod_auth_pgsql_sys\30.9.5\5some place\7",
			 string:report);
			 
		
   security_hole(port:port, extra:r);
}
