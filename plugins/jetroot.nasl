#
# This buggy script was written by Laurent FACQ (@u-bordeaux.fr)
#
# Based on :  http://www.nessus.org/u?18f0ad6f
#       " Phenoelit HP Web JetAdmin 6.5 remote\n".
#       " Linux root and Windows NT/2000 Administrator exploit\n".
#       " by FX of Phenoelit\n".
#       " Research done at BlackHat Singapore 2002\n\n";
#
# Changes by Tenable:
# - Revised plugin title, changed family, fixed summary, updated copyright (1/21/2009)


include("compat.inc");

if (description)
{
  script_id(12227); 
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/01/14 15:43:29 $");

  script_bugtraq_id(9973, 10224);
  script_osvdb_id(
    5790,
    5791,
    5792,
    5793,
    5794,
    5795,
    5796,
    5797,
    5798
  );

  script_name(english:"HP Web JetAdmin <=7.0 Multiple Vulnerabilities (XSS, Code Exe, DoS, more)");
  script_summary(english:"HP JetAdmin 7.0 or less vulnerability");

  script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote HP Web Jetadmin is vulnerable to multiple exploits.  This
includes, but is not limited to, full remote administrative access.  An
attacker can execute code remotely with SYSTEM level (or root)
privileges by invoking the ExecuteFile function.  To further exacerbate
this issue, there is working exploit code for multiple vulnerabilities
within this product.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7bedb551");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/15989");
  script_set_attribute(attribute:"solution", value:"The issues are resolved in HP Web Jetadmin version 7.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"(C) 2004-2015 facq");
  script_family(english:"CGI abuses");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8000);
  exit(0);
}


include("http_func.inc");

function debug_print()
{
  local_var a;
  a = _FCT_ANON_ARGS[0];
}

# Check starts here

port = 8000;
if(!get_port_state(port))exit(0);

r = http_send_recv(port:port, data:string("GET /plugins/hpjwja/help/about.hts HTTP/1.0\r\n\r\n"));

if(r == NULL) { 
    #display ("\n\nexit null\n\n"); 
    exit(0); 
}

if((r =~ "HTTP/1.[01] 200") && ("Server: HP-Web-Server" >< r))
{
    r= ereg_replace(pattern:"<b>|</b>", string:r, replace: "<>");
    r= ereg_replace(pattern:"<[^>]+>", string:r, replace: "");
    r= ereg_replace(pattern:"[[:space:]]+", string:r, replace: " ");
    r= ereg_replace(pattern:" <>", string:r, replace: "<>");
    r= ereg_replace(pattern:"<> ", string:r, replace: "<>");

    #display(r); # debug
    #display("\n\n"); # debug

    if (
        (r =~ "<>HP Web JetAdmin Version<>6.5") # tested
        ||
        (r =~ "<>HP Web JetAdmin Version<>6.2") # not tested
        ||
        (r =~ "<>HP Web JetAdmin Version<>7.0") # not tested
        )

    {
        #display("\nhole \n"); # debug
        security_hole(port);
    }
}

