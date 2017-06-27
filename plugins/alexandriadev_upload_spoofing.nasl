#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: Thomas Kristensen <tk@secunia.com>
# To: vulnwatch@vulnwatch.org
# Date: 28 Mar 2003 14:54:33 +0100
# Subject: [VulnWatch] Alexandria-dev / sourceforge multiple vulnerabilities


include("compat.inc");

if(description)
{
 script_id(11498);
# Related BIDs: 7223 = XSS, 7224 = CRLFi, 7225 = upload spoofing
 script_bugtraq_id(7225);
 script_osvdb_id(49225, 49226, 49228, 49229);
 script_xref(name:"Secunia", value:"8436");
 script_version ("$Revision: 1.24 $");


 script_name(english:"Alexandria-dev Multiple Script Upload Spoofing Arbitrary File Access");
 script_summary(english:"Checks for the presence of patch/index.php and docman/new.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running Alexandria-Dev, an open source
project management system.

The CGIs 'docman/new.php' and 'patch/index.php' can be used by an attacker
with the proper credentials to upload a file and trick the server
about its real location on the disk. Therefore, an attacker may use
this flaw to read arbitrary files on the remote server.

*** Nessus solely relied on the presence of this CGI to issue
*** this alert, so this might be a false positive." );
 script_set_attribute(attribute:"see_also", value:
"http://seclists.org/fulldisclosure/2003/Mar/275");
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/28");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);


dirs = make_list(cgi_dirs(), "/SF2.5", "/sf");



foreach dir (dirs)
{
 w = http_send_recv3(method:"GET", item:string(dir, "/docman/new.php"), port:port);			
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if("No group_id" >< r){security_warning(port); exit(0);}
 
 w = http_send_recv3(method:"GET", item:string(dir, "/patch/index.php"), port:port);			
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if("No Group Id" >< r){ security_warning(port); exit(0); }
}
