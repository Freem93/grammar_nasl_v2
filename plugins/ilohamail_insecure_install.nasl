#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(16161);
  script_version("$Revision: 1.11 $");
  script_bugtraq_id(12252);
  script_osvdb_id(12870);
  script_xref(name:"Secunia", value:"13807");
  script_name(english:"IlohaMail Configuration Scripts Remote Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a webmail application that is affected by 
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Ilohamail, a web-based mail interface
written in PHP.

The remote installation of this software is not configured properly,
in the sense that it allows any user to download its configuration
files by requesting the '/conf/conf.inc' or '/conf/custom_auth.inc'
file.  The  content of these files may contain sensitive information
which may help an attacker to organize better attacks against the
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jan/118" );
 script_set_attribute(attribute:"solution", value:
"Prevent the download of .inc files at the web server level." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/11");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for the presence of conf/conf.inc");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

# use ilohamail_conf_files_readable.nasl instead
exit (0);

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

res = http_send_recv3(method:"GET", item:"/conf/conf.inc", port:port, exit_on_fail :1);

if (egrep(pattern:"\$backend *=", string:res[2]) &&
    egrep(pattern:"\$USER_DIR", string:res[2]))
  security_warning(port);
