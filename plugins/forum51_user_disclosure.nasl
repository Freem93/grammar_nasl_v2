#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11796);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2016/12/08 20:31:54 $");

 script_bugtraq_id(8126, 8127, 8128);
 script_osvdb_id(2292);
 script_xref(name:"Secunia", value:"9253");

 script_name(english:"Forum51/Board51/News51 Users Disclosure");
 script_summary(english:"Checks for the presence of user.idx");
 
 script_set_attribute( attribute:"synopsis", value:
"A web application running on the remote host has an information
disclosure vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The remote web server is running a bulletin board application
(Forum51, Board51, or News51) with an information disclosure
vulnerability.  It is possible to retrieve usernames and password
hashes by requesting '/data/user.idx'.  A remote attacker could use
this information to mount further attacks." );
 # https://web.archive.org/web/20051104180522/http://archives.neohapsis.com/archives/bugtraq/2003-07/0078.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?ca8aee52"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Restrict public access to the '/data' directory."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/07/21");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

#
# The script code starts here
#
port = get_http_port(default:80);
dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 foreach subdir (make_list("forumdata", "boarddata", "newsdata"))
 {
   url = strcat(dir, "/", subdir, "/data/user.idx");
   res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

   if (strlen(res[2]) == 0) continue;
   if (!ereg(pattern:"^[0-9a-fA-F]{32}", string:res[2])) continue;

   foreach line (split(res[2], keep:FALSE))
   {
     if (";" >!< line || "@" >!< line) continue;
     if (!ereg(pattern:"^[0-9a-fA-F]{32}", string:line)) continue;

     fields = split(line, sep:";", keep:FALSE);
     nfields = max_index(fields);

     if (
       (nfields >= 7 && "@" >< fields[1] && fields[2] =~ "^[0-9]*$" && fields[4] =~ "^[0-9]*$" && fields[5] =~ "^[0-9]*$") ||
       (nfields >= 4 && "@" >< fields[3] && fields[0] =~ "^[0-9]*$")
     )
     {
       if (report_verbosity > 0)
       {
         report = '\n  URL : ' + build_url(port:port, qs:url) +
                  '\n  Sample line : ' + line +
                  '\n';
         security_warning(port:port, extra:report);
       }
       else security_warning(port);
       exit(0);
     }
   }
 }
}

exit(0, "The web server listening on port "+port+" is not affected.");
