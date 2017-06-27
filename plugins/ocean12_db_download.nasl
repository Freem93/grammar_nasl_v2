#
# (C) Tenable Network Security, Inc.
#

# Ref: 
#  From: "drG4njubas" <drG4nj@mail.ru>
#  To: <bugtraq@securityfocus.com>
#  Subject: Ocean12 ASP Guestbook Manager v1.00
#  Date: Fri, 11 Apr 2003 16:29:16 +0400



include("compat.inc");

if(description)
{
 script_id(11599);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(7328);
 script_osvdb_id(52975);
 
 script_name(english:"Ocean12 ASP Guestbook Manager Database Download");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has an application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server is running Ocean12 GuestBook, a set of scripts
to manage an interactive guestbook.

An attacker may download the database 'o12guest.mdb' 
and use it to extract the password of the admninistrator
of these CGIs." );
 script_set_attribute(attribute:"solution", value:
"Block the download of .mdb files from your web server." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/07");
 script_cvs_date("$Date: 2017/01/30 23:05:16 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for Ocean12 guestbook";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

dirs = make_list(cgi_dirs(), "/guestbook");

foreach d (dirs)
{
 res = http_send_recv3(method:"GET", item:string(d, "/admin/o12guest.mdb"), port:port);

 if (isnull(res)) exit(1,"Null response for 012guest.mdb request.");
 if("Standard Jet DB" >< res[2])
 {
  security_warning(port);
  exit(0);
 }
}
