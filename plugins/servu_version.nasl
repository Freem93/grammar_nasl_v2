#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48434);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2011/12/09 02:48:39 $");

  script_name(english:"Serv-U Version Detection");
  script_summary(english:"Obtains the version of the remote Serv-U install");

  script_set_attribute(
    attribute:"synopsis",
    value: "The remote FTP server is Serv-U File Server."
  );
  script_set_attribute(
    attribute:"description",
    value: 
"Serv-U File Server, an FTP server for Windows, is listening on this
port, and it is possible to determine its version."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.serv-u.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");
include("misc_func.inc");

kb_data = make_array();
ports = get_kb_list("Services/ftp");

if (isnull(ports)) ports = make_list(21);

foreach port (ports)
{
  if (get_kb_item('ftp/'+port+'/backdoor')) continue;

  if (!get_port_state(port)) continue;

  banner = get_ftp_banner(port:port);
  if (!banner) continue; # broken

  matches = eregmatch(
    pattern:"^.*Serv-U FTP( |-Server | Server )v[ ]*(([0-9a-z-]+\.)+[0-9a-z]+)(.*$|$)", 
    string:banner, 
    icase:TRUE
  );
  if (matches)
  {
    kb_data['ftp/'+port+'/servu'] = 1;
    kb_data['ftp/'+port+'/servu/banner/source'] = chomp(banner);
    kb_data['ftp/'+port+'/servu/banner/version'] = matches[2];
  }

  if (kb_data['ftp/'+port+'/servu/banner/version'])
  {
    kb_data['ftp/'+port+'/servu/version'] = kb_data['ftp/'+port+'/servu/banner/version'];
    kb_data['ftp/'+port+'/servu/source']  = kb_data['ftp/'+port+'/servu/banner/source'];
  }

  # Now try with CSID cmd
  sock = open_sock_tcp(port);
  if (!sock) continue;

  w = ftp_send_cmd(socket:sock, cmd:"CSID Name=NESSUS;");
  if (ereg(pattern:"^220 ", string:w)) w = ftp_recv_line(socket:sock);
  close(sock);

  if (!w || "Name=Serv-U" >!< w) continue;

  kb_data['ftp/'+port+'/servu'] = 1;
  kb_data['ftp/'+port+'/servu/csid/source'] = chomp(w);

  foreach item (split(w, sep:'; ', keep:FALSE))
  {
    if ('Version=' >< item)
      kb_data['ftp/'+port+'/servu/csid/version'] = strstr(item, "Version=") - "Version=";
  }

  # Use CSID if possible (overwrite data from banner)
  if (kb_data['ftp/'+port+'/servu/csid/version']) 
  {
    kb_data['ftp/'+port+'/servu/version'] = kb_data['ftp/'+port+'/servu/csid/version'];
    kb_data['ftp/'+port+'/servu/source']  = kb_data['ftp/'+port+'/servu/csid/source'];
  }
}

if (max_index(keys(kb_data)) > 0)
{
  # nb: make sure we flag the host as having Serv-U.
  replace_kb_item(name:"ftp/servu", value:TRUE);

  foreach k (keys(kb_data))
    replace_kb_item(name:k, value:kb_data[k]);
}
else exit(0, "Serv-U does not appear to be running on this host.");
