#TRUSTED 3b9f512bddb923faf649ccdd99112f533ae39b80632033a443c1d3df635f2b9436516070d5651f7bceabea3f7bbada6ce250390224ea514548e08ca7bd0691177fcb5f2d697045bfc6a410b14e50d982a1b3ef2fb3a63d32ffb9ed8f83255758208cbbef667e5642b1ce535b5869c54dd464c0d0d75a894718fdfe0dd7b99f5fda09fdc07de1ea889a7f4bfc1cbea9682400543b1d67abe31c8ca0786b52e482d57054a6c194620f62303cf0ddb9f5e6664e5e03fa744384e37b041c70017076c0977d9e30e1ad09ee56470a835f36a24434763acf398471b163b6b860b8aeda27ddb1957901b9fc9093f0768bda2b62af51ee9f43084863b4431af785c76f0d7ef23bb7d4cfa5fd9d4af75903d274d834396e7d947936b68f665f3575efc33cdc033c83dcd49fa33b4e31d3637cc4e6f4a2429f2f6d4e966a6ec09d84b594d2eb1086292dd8867aeb69123f4a9141c5ec02ce747ca588b6144628165624e1d4038406d526ce3dbec815308112ee025d4a64f1b0684f923fa2683dc68b3df35fa41d59a428793c5e43a10c0183a8851024775796321b571f08c11ae75e7bb8e15a0b760d95f0fa55f66b956ab51afb8283ef24b4ffea6daf2b3572ad4352917ac6ebc19b1cc280009667236befe96f7605201122031a5f19df87d8e0b4393038e8188f657d064fc00dbb5a4b18c4edb3e08f680d2241a7128403fa0acb8d7a27
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{

 script_id(12634);
 script_version("2.303");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/25");

 script_name(english:"Authenticated Check : OS Name and Installed Package Enumeration");
 script_summary(english:"Obtains the remote OS name and installed packages.");

 script_set_attribute(attribute:'synopsis', value:
"This plugin gathers information about the remote host via an
authenticated session.");
 script_set_attribute(attribute:'description', value:
"This plugin logs into the remote host using SSH, RSH, RLOGIN, Telnet,
or local commands and extracts the list of installed packages.

If using SSH, the scan should be configured with a valid SSH public
key and possibly an SSH passphrase (if the SSH public key is protected
by a passphrase).");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Settings");

 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");

 script_dependencies("find_service1.nasl", "ssh_settings.nasl", "clrtxt_proto_settings.nasl", "os_fingerprint_ssh_netconf.nasl");

 # Patch Management plugins that might set package info and enable local checks.
 if (defined_func("xmlparse")) script_dependencies("satellite_settings.nbin", "vmware_installed_patches.nbin", "vmware_installed_vibs.nbin", "ibm_tem_get_packages.nbin");
 if (NASL_LEVEL >= 5200) script_dependencies("symantec_altiris_get_packages.nbin");
 if (NASL_LEVEL >= 6000) script_dependencies("satellite_6_get_packages.nbin");

 # script_require_ports(22, "Services/ssh", 23, "Services/telnet", 512, 513, 514);
 exit(0);
}

include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("agent.inc");

function _local_checks_enabled()
{
  set_kb_item(name:'Host/local_checks_enabled', value: TRUE);
  if (defined_func('report_xml_tag'))
    report_xml_tag(tag:"Credentialed_Scan", value:"true");
}

# If plugin debugging is enabled, enable packet logging
if(get_kb_item("global_settings/enable_plugin_debugging"))
  SSH_LOG_PACKETS = TRUE;

# If we already collected patch info from the SOAP API, we're done.
if (
  get_kb_item("Host/VMware/esxcli_software_vibs") ||
  get_kb_item("Host/VMware/esxupdate")
)
{
  report += '\nLocal security checks have been enabled for this host.';
  # nb: remove any failure message from the SOAP checks.
  rm_kb_item(name:"HostLevelChecks/failure");
  _local_checks_enabled();
  security_note(port:0, extra:report);
  exit(0);
}

# the OS has already been identified via netconf
# netconf can be used with transports other than SSH, so if additional plugins
# are written in the future to use those transports, this code needs to be updated
if (netconf_os = get_kb_item('Host/netconf/' + kb_ssh_transport() + '/os'))
{
  if (netconf_os == 'Juniper IVE OS')
  {
    report += '\nLocal security checks have been enabled for ' + netconf_os + '.';
    _local_checks_enabled();
  }
  else
  {
    report += '\nLocal security checks have NOT been enabled for ' + netconf_os + '.';
  }

  security_note(port:0, extra:report);
  exit(0);
}

##
# Tries to collect MAC address lists for various CISCO devices
#
# @param systype string hinting at what type of device this
#        (CISCO IOS / ASA / IOSXR / etc)
#
# @return NULL (no return value)
##
function get_cisco_mac_addrs(systype)
{
  if(isnull(systype))
    systype = _FCT_ANON_ARGS[0];

  local_var ciscomac = "([a-f0-9A-F]{4}\.[a-f0-9A-F]{4}\.[a-f0-9A-F]{4})";
  # Most common command and pattern
  local_var infcmd   = "show interface";
  local_var regex    = "^[ \t]*Hardware.*address is "+ciscomac;
  # Some temps for processing
  local_var line     = NULL;
  local_var infbuf   = NULL;
  local_var macs     = make_array();
  local_var mlist    = "";
  local_var matches  = NULL;
  # Variations based on systype
  if(systype == "NX-OS")
  {
    infcmd = "show interface";
    regex  = "^[ \t]*Hardware.*address: "+ciscomac;
  }
  else if(systype =~ "^(ASA|FWSM)$")
  {
    infcmd = "show interface";
    regex  = "[ \t]*MAC address "+ciscomac;
  }

  # many CISCO devices need the connection refreshed
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  infbuf = ssh_cmd(cmd:infcmd, nosudo:TRUE, nosh:TRUE, cisco:TRUE);
  infbuf = split(infbuf, sep:'\n', keep:FALSE);
  foreach line (infbuf)
  {
    matches = eregmatch(string:line, pattern:regex);
    if(max_index(matches) > 1)
      macs[matches[1]] = TRUE;
  }

  foreach line (keys(macs))
    mlist += line+',';
  mlist = ereg_replace(string:mlist, pattern:",$", replace:"");
  replace_kb_item(name:"Host/raw_macs", value:mlist);
}

##
# Tries to collect MAC address lists for JunOS
#
# @param shell the remote system is using sh/bash over cli
#
# @return NULL (no return value)
##
function get_junos_mac_addrs(shell)
{
  if(isnull(shell))
    shell = _FCT_ANON_ARGS[0];

  local_var ifconmac = "(([a-f0-9A-F]{2}[:-]){5}[a-f0-9A-F]{2})";
  # Most common command and pattern
  local_var infcmd   = "show interface";
  local_var regex    = "Hardware address: "+ifconmac;
  # Some temps for processing
  local_var line     = NULL;
  local_var infbuf   = NULL;
  local_var macs     = make_array();
  local_var matches  = NULL;
  local_var mlist    = "";

  # If we're running on bash / sh commands need to be
  # prefixed with 'cli'
  if(shell)
    infbuf = ssh_cmd(cmd:"cli "+infcmd, nosudo:TRUE);
  else
    infbuf = ssh_cmd(cmd:infcmd, nosudo:TRUE, nosh:TRUE);

  infbuf = split(infbuf, sep:'\n', keep:FALSE);
  foreach line (infbuf)
  {
    matches = eregmatch(string:line, pattern:regex);
    if(max_index(matches) > 1)
      macs[matches[1]] = TRUE;
  }

  foreach line (keys(macs))
    mlist += line+',';
  mlist = ereg_replace(string:mlist, pattern:",$", replace:"");
  replace_kb_item(name:"Host/raw_macs", value:mlist);
}

#Gentoo helper functions
function extract_gentoo_portdir(buf)
{
  local_var     lines, portdir, gr, len;

  gr = egrep(string: buf, pattern: '^[ \t]*PORTDIR[ \t]*=[ \t]*');
  # Keep the last line, just in case
  lines = split(gr, keep: 0);
  portdir = lines[max_index(lines)-1];
  lines = split(portdir, sep: '=', keep: 0);
  portdir = lines[1];
  len = strlen(portdir);
  if ( portdir[0] == "'" && portdir[len-1] == "'" ||
       portdir[0] == '"' && portdir[len-1] == '"' )
   portdir = substr(portdir, 1, len-2);
  return portdir;
}

# Avaya helper functions

##
# Determines if the system is an Avaya appliance
#
# @remark Based on our current detection. Add additional Avaya detection
#         to this function when we get more concrete data.
#
# @param redhat_release Copy of the redhat-release contents for determining OS
#
# @return TRUE if The SystemDescription \"Avaya string is found in /etc/ecs.conf
#         FALSE otherwise
##
function check_avaya(redhat_release)
{
  local_var avayadevice, avayaversion, ecs_contents;
  # Identify Avaya Communications Systems
  if (isnull(redhat_release) || !strlen(redhat_release)) return FALSE;
  if (egrep(pattern:"Red Hat.*(Enterprise|Advanced)|CentOS", string:redhat_release))
  {
    ecs_contents = info_send_cmd(cmd:"cat /etc/ecs.conf");
    if ( ecs_contents && strlen(ecs_contents) && 'SystemDescription "Avaya' >< ecs_contents )
    {
      avayadevice = avayaversion = NULL;
      avayadevice = strstr(ecs_contents, 'SystemDescription "Avaya') - 'SystemDescription "';
      avayadevice = avayadevice - strstr(avayadevice, '"');

      if ("Version" >< ecs_contents)
      {
        avayaversion = strstr(ecs_contents, 'Version') - 'Version';
        avayaversion = avayaversion - strstr(avayaversion, "CDA");
        avayaversion = chomp(avayaversion);
      }
      if ( !isnull(avayadevice) && strlen(avayadevice) && !isnull(avayaversion) && strlen(avayaversion) )
        set_kb_item(name:'Host/'+avayadevice+'/Version', value:avayaversion);

      # As long as we detected Avaya in the SystemDescription of /etc/ecs.conf,
      # return true.
      return TRUE;
    }
  }
  return FALSE;
}

#------------------------------------------------------------------------#
# Misc calls (all Unixes)                                                #
#------------------------------------------------------------------------#

# cfengine version

global_var release, has_redhat_release;

has_redhat_release = FALSE;

function misc_calls_and_exit()
{
 local_var buf, cmd, error_msg, ip_addr, ver;

 ver = info_send_cmd(cmd:"/usr/sbin/cfservd --help | grep ^cfengine | cut -d '-' -f 2");
 if ( ver )
  {
   ver = chomp(ver);
   set_kb_item(name:string("cfengine/version"), value:ver);
  }

 ver = info_send_cmd(cmd:"/etc/init.d/guiSvr version");
 if ( ver )
 {
   ver = chomp(ver);
   set_kb_item(name:'Host/NSM/guiSvr/version_src', value:ver);
 }

 ver = info_send_cmd(cmd:"/etc/init.d/devSvr version");
 if ( ver )
 {
   ver = chomp(ver);
   set_kb_item(name:'Host/NSM/devSvr/version_src', value:ver);
 }

 local_var ifconfig_kb_set = FALSE;
 if ("AIX-" >< release)
 {
   cmd = '/etc/ifconfig -a';
   buf = info_send_cmd(cmd:cmd);
   if (buf && "not found" >!< buf)
   {
     set_kb_item(name:"Host/ifconfig", value:buf);
     ifconfig_kb_set = TRUE;
   }
   cmd = '/usr/bin/netstat -ian';
   buf = NULL;
   buf = info_send_cmd(cmd:cmd);
   if (buf) set_kb_item(name:"Host/netstat-ian", value:buf);
 }
 else if ('HP-UX' >< uname_a)
 {
   cmd = '/usr/bin/netstat -ian';
   buf = info_send_cmd(cmd:cmd);
   if (buf) set_kb_item(name:"Host/netstat-ian", value:buf);
   # IPv6
   buf = NULL;
   cmd = '/usr/bin/netstat -ianf inet6';
   buf = info_send_cmd(cmd:cmd);
   if (buf) set_kb_item(name:"Host/netstat-ianf-inet6", value:buf);
   # nwmgr
   buf = NULL;
   cmd = '/usr/sbin/nwmgr';
   buf = info_send_cmd(cmd:cmd);
   if (buf) set_kb_item(name:"Host/nwmgr", value:buf);
   # lanscan
   buf = NULL;
   cmd = '/usr/sbin/lanscan -ai';
   buf = info_send_cmd(cmd:cmd);
   if (buf) set_kb_item(name:"Host/lanscan-ai", value:buf);
 }

 if (!ifconfig_kb_set)
 {
   cmd = '/sbin/ifconfig -a';
   buf = info_send_cmd(cmd:cmd);
   if (!buf && "Gentoo" >< release)
   {
     cmd = '/bin/ifconfig -a';
     buf = info_send_cmd(cmd:cmd);
   }

   if (buf && "not found" >!< buf)
     set_kb_item(name:"Host/ifconfig", value:buf);

   if(!buf || "not found" >< buf)
   {
      cmd = '/sbin/ip addr show';
      buf = info_send_cmd(cmd:cmd);
      if(buf) set_kb_item(name:"Host/ifconfig", value:buf);
   }
 }

 if (agent())
 {
   ip_addr = agent_get_ip();
   if (!isnull(ip_addr))
     report_xml_tag(tag:"host-ip", value:ip_addr);
 }

 buf = info_send_cmd(cmd:'/bin/hostname');
 if ( buf ) buf = chomp(buf);
 if ( buf ) set_kb_item(name:'Host/hostname', value:buf);

 if (info_t == INFO_SSH) ssh_close_connection();
 exit(0);
}

report = "";
info_t = 0;

#### Choose "transport" ####

error_msg = "";
ssh_banner = "";
ssh_failed = 0;
telnet_failed = 0;
port_g = NULL;
sock_g = NULL;

if (islocalhost() && defined_func("fread") && defined_func("pread"))
{
 info_t = INFO_LOCAL;
 set_kb_item(name: 'HostLevelChecks/proto', value: 'local');
 if ( defined_func("report_xml_tag") ) report_xml_tag(tag:"local-checks-proto", value:"local");
}

if (! info_t)
{
 if (defined_func("bn_random"))
 {
  port22 = kb_ssh_transport();
  if ( port22 && get_port_state(port22) )
  {
   soc = open_sock_tcp(port22);
   if ( soc )
   {
     ssh_banner = recv_line(socket:soc, length:1024);

     if (ssh_banner == "" || isnull(ssh_banner))
       ssh_banner = recv_line(socket:soc, length:1024, timeout:10);

     close(soc);

     if ( "-Cisco-" >< ssh_banner )
     {
       CISCO++;
       if ("-Cisco-2." >< ssh_banner) CISCO_IOS_XR++;
     }
     if ("-CISCO_WLC" >< ssh_banner)
     {
       CISCO_WLC = TRUE;
       rm_kb_item(name:"SSH/login/failed");
     }
   }
  }

  # nb: needed for Cisco Wireless LAN Controllers and Sonicwall.
  if (!CISCO || CISCO_WLC)
  {
    set_kb_item(name:"/tmp/ssh/try_none", value:TRUE);
    timeout = get_ssh_read_timeout();
    if (timeout <= 5) set_ssh_read_timeout(10);
  }

  # nb: needed for Cisco IOS XR
  if (CISCO_IOS_XR) sleep(1);

  if ("force10networks.com" >< ssh_banner) sleep(1);

  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);

  # nb: Sonicwall needs a delay between the initial banner grab
  #     and  calling 'ssh_open_connection()'.
  if (
    !sock_g &&
    "please try again" >< get_ssh_error()
  )
  {
    for (i=0; i<5 && !sock_g; i++)
    {
      # We need to unset login failure if we are going to try again
      if(get_kb_item("SSH/login/failed")) rm_kb_item(name:"SSH/login/failed");
      sleep(i*2);
      sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    }
  }

  private_key = kb_ssh_privatekey();
 }
 if (sock_g)
 {
  info_t = INFO_SSH;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'ssh');
  set_kb_item(name:"HostLevelChecks/login", value:kb_ssh_login());
  if ( defined_func("report_xml_tag") ) {
        report_xml_tag(tag:"local-checks-proto", value:"ssh");
        report_xml_tag(tag:"ssh-login-used", value:kb_ssh_login());
        if ( kb_ssh_privatekey() )
                report_xml_tag(tag:"ssh-auth-meth", value:"private-key");
        else
                report_xml_tag(tag:"ssh-auth-meth", value:"password");
  }
  port_g = port22;
 }
 else
 {
  ssh_failed = 1;
  pass_needs_change = FALSE;

  if ( kb_ssh_login() && ( kb_ssh_password() || kb_ssh_privatekey() )  )
  {
    error_msg = get_ssh_error();
    if (error_msg)
    {
      if (
        "password" >< error_msg &&
        "must be changed" >< error_msg
      )
      {
        set_kb_item(name:'HostLevelChecks/failure', value:error_msg);
        pass_needs_change = TRUE;
      }
      else
      {
        set_kb_item(name: 'HostLevelChecks/ssh/failed', value:TRUE);
        set_kb_item(name: 'HostLevelChecks/ssh/error_msg', value:error_msg);
      }
    }
  }
  CISCO = FALSE; # Only try Cisco over SSH

  if (!pass_needs_change)
  {
    try_telnet = get_kb_item("HostLevelChecks/try_telnet");
    try_rlogin = get_kb_item("HostLevelChecks/try_rlogin");
    try_rsh    = get_kb_item("HostLevelChecks/try_rsh");
    try_rexec  = get_kb_item("HostLevelChecks/try_rexec");
    login      = get_kb_item("Secret/ClearTextAuth/login");
    pass       = get_kb_item("Secret/ClearTextAuth/pass");
  }
 }
}

if (! info_t && try_rlogin && strlen(login) > 0)
{
 port513 = get_kb_item("Services/rlogin");
 if (! port513) port513 = 513;

 sock_g = rlogin(port: port513, login: login, pass: pass);
 if (sock_g)
 {
  info_t = INFO_RLOGIN;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'rlogin');
  set_kb_item(name:"HostLevelChecks/login", value:login);
  if ( defined_func("report_xml_tag") ) {
        report_xml_tag(tag:"local-checks-proto", value:"rlogin");
        report_xml_tag(tag:"rlogin-login-used", value:login);
  }
  port_g = port513;
 }
 else
  {
  set_kb_item(name: 'HostLevelChecks/rlogin/failed', value:TRUE);
  rlogin_failed = 1;
  }
}

if (! info_t && try_rsh && strlen(login) > 0 )
{
 port514 = get_kb_item("Services/rsh");
 if (! port514) port514 = 514;
 r = send_rsh(port: port514, cmd: 'id');
 if ("uid=" >< r)
 {
  info_t = INFO_RSH;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'rsh');
  set_kb_item(name:"HostLevelChecks/login", value:login);
  if ( defined_func("report_xml_tag") ) {
        report_xml_tag(tag:"local-checks-proto", value:"rsh");
        report_xml_tag(tag:"rsh-login-used", value:login);
  }
  port_g = port514;
 }
 else
  {
  set_kb_item(name: 'HostLevelChecks/rsh/failed', value:TRUE);
  rsh_failed = 1;
  }
}

if (! info_t && try_rexec && strlen(login) > 0)
{
 port512 = get_kb_item("Services/rexec");
 if (! port512) port512 = 512;
  r = send_rexec(port: port512, cmd: 'id');
 if ("uid=" >< r)
 {
  info_t = INFO_REXEC;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'rexec');
  set_kb_item(name:"HostLevelChecks/login", value:login);
  if ( defined_func("report_xml_tag") ) {
        report_xml_tag(tag:"local-checks-proto", value:"rexec");
        report_xml_tag(tag:"rexec-login-used", value:login);
  }
  port_g = port512;
 }
 else
  {
  set_kb_item(name: 'HostLevelChecks/rexec/failed', value:TRUE);
  rexec_failed = 1;
  }
}

if (! info_t && try_telnet && strlen(login) > 0 && strlen(pass) > 0)
{
 port23 = get_kb_item("Services/telnet");
 if (! port23) port23 = 23;
  sock_g = telnet_open_cnx(port: port23, login: login, pass: pass);
 if (sock_g)
 {
  info_t = INFO_TELNET;
  set_kb_item(name: 'HostLevelChecks/proto', value: 'telnet');
  set_kb_item(name:"HostLevelChecks/login", value:login);
  if ( defined_func("report_xml_tag") ) {
        report_xml_tag(tag:"local-checks-proto", value:"telnet");
        report_xml_tag(tag:"telnet-login-used", value:login);
  }
  port_g = port23;
 }
 else
 {
  set_kb_item(name: 'HostLevelChecks/telnet/failed', value:TRUE);
  telnet_failed = 1;
 }
}

#

if (info_t == INFO_LOCAL)
  report = 'Nessus can run commands on localhost to check if patches are applied.\n';
else if (info_t == INFO_SSH && private_key)
  report = 'It was possible to log into the remote host using the supplied\nasymmetric keys.\n';
else
  report = 'It was possible to log into the remote host using the supplied\npassword.\n';

if ( info_t == 0 )
{
  if (strlen(error_msg)) exit(1, error_msg);
  else exit(1, "Unknown failure (try reducing Max Checks Per Host and increasing Network Receive Timeout).");
}

# Determine the remote operating system type
# Windows is not supported
if ( info_t == INFO_SSH && !CISCO && !SONICWALL_SSH)
{
 buf = ssh_cmd(cmd: 'cmd /C ver', nosh:TRUE, nosudo:TRUE, noexec:TRUE, allow_aos:TRUE);
 if ( buf && ("Microsoft Windows" >< buf)) exit(0, "Credentialed checks of Windows are not supported using SSH.");
}

# Determine if this is PalAlto 6+, if it is sending the ECHO terminal mode will cause the server
# to abruptly close the session, the symptoms of these are that there is nothing in buf and
# nothing in ssh_error.
SSH_GET_INFO_PANOS_BUGGED = FALSE;
if( info_t == INFO_SSH && !CISCO && !SONICWALL_SSH && !buf && !get_ssh_error())
{
  # Running the same command as above is more compatible with the rest of
  # the code, should something else strange happen.
  buf = ssh_cmd(cmd: 'cmd /C ver', nosh:TRUE, nosudo:TRUE, noexec:TRUE, no53:TRUE);
  if("Unknown command: cmd" >< buf) SSH_GET_INFO_PANOS_BUGGED = TRUE;
}

# UCS Director has a shell script menu
if("Cisco UCS Director Shell Menu" >< buf)
{
  # restart connection in order to send command properly
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  buf = ssh_cmd(cmd:'11', nosh:TRUE, nosudo:TRUE, noexec:TRUE);
  ssh_close_connection();
  version = eregmatch(pattern:"Version\s+: ([0-9.]+)",  string:buf);
  build   = eregmatch(pattern:"Build Number\s+: ([0-9]+)", string:buf);
  if (!isnull(version) && !isnull(build))
  {
    set_kb_item(name:"Host/Cisco/UCSDirector/version" , value:version[1]);
    set_kb_item(name:"Host/Cisco/UCSDirector/build"   , value:build[1]);

    report += '\n' + 'Although local, credentialed checks for CISCO UCS Director are not available,' +
              '\n' + 'Nessus has managed to run commands in support of OS fingerprinting.' +
              '\n';
    security_note(port:0, extra:report);
  }
  exit(0);
}

# Cisco Prime NSC
# and Cisco UCS Server Manager, maybe others
if("% Invalid Command at '^' marker" >< buf)
{
  buf_pnsc = ssh_cmd(cmd:'connect local-mgmt', nosh:TRUE, nosudo:TRUE, noexec:TRUE, no53:TRUE);
  if ("Cisco Prime Network Services Controller" >< buf_pnsc)
  {
    buf_pnsc = ssh_cmd(cmd:'show version', nosh:TRUE, nosudo:TRUE, noexec:TRUE, no53:TRUE);
    ssh_close_connection();

    version = eregmatch(pattern:"core\s+Base System\s+([0-9]+\.[0-9]+\([0-9]+[a-z]\))\s+",  string:buf_pnsc);
    if (!isnull(version))
    {
      set_kb_item(name:"Host/Cisco/Prime NSC/version" , value:version[1]);
      set_kb_item(name:"Host/Cisco/Prime NSC/source", value:version[0]);

      report += '\n' + 'Although local, credentialed checks for CISCO Prime NSC are not available,' +
                '\n' + 'Nessus has managed to run commands in support of OS fingerprinting.' +
                '\n';
      security_note(port:0, extra:report);
    }
    exit(0);
  }
  else if("Cisco Nexus Operating System (NX-OS) Software" >< buf_pnsc)
  {
    buf_pnsc_orig = buf_pnsc; # original value
    buf_pnsc = ssh_cmd(cmd:'show version', nosh:TRUE, nosudo:TRUE, noexec:TRUE, cisco:TRUE, no53:TRUE);
    if (!isnull(buf_pnsc) && strlen(buf_pnsc) > 0)
    {
      # fix up this output to include NX-OS banner (if it doesn't already)
      if ("Cisco Nexus Operating System (NX-OS) Software" >!< buf_pnsc)
        buf_pnsc = buf_pnsc_orig + '\r\n' + buf_pnsc;

      set_kb_item(name:"Host/Cisco/show_ver", value:buf_pnsc);
      set_kb_item(name:"Host/Cisco/NX-OS", value:TRUE);
      ssh_close_connection();

      _local_checks_enabled();
      report += '\nLocal security checks have been enabled for Cisco NX-OS.\n';
      security_note(port:0, extra:report);
    }
    exit(0);
  }
}

if ( AOS_SSH == TRUE )
{
  # special kid glove handling for older AOS devices
  # we may not get a second chance to reconnect on these
  cmd = 'show microcode\r\n';
  send_ssh_packet(payload:'\0\0\0\0', code:raw_int8(i:SSH_MSG_IGNORE));
  payload = raw_int32(i:remote_channel) + putstring(buffer:cmd + 'exit\r\n');
  send_ssh_packet(payload:payload, code:raw_int8(i:SSH2_MSG_CHANNEL_DATA));

  show_ver = "";

  buf = recv_ssh_packet(timeout:timeout);
  while(ord(buf[0]) == SSH2_MSG_CHANNEL_DATA)
  {
    show_ver += getstring(buffer:buf, pos:5);
    if('\r\n\r\n' >< show_ver) break;
    buf = recv_ssh_packet(timeout:timeout);
  }

  # disconnect politely, or it will start blocking out SSH tcp connections
  while(ord(buf[0]) == SSH2_MSG_CHANNEL_DATA || ord(buf[0]) == SSH2_MSG_CHANNEL_EOF || ord(buf[0]) == SSH2_MSG_CHANNEL_CLOSE)
  {
    if(ord(buf[0]) == SSH2_MSG_CHANNEL_EOF)
    {
      send_ssh_packet(payload:'\0\0\0\0', code:raw_int8(i:SSH2_MSG_CHANNEL_EOF));
      send_ssh_packet(payload:'\0\0\0\0', code:raw_int8(i:SSH2_MSG_CHANNEL_CLOSE));
    }
    else if(ord(buf[0]) == SSH2_MSG_CHANNEL_CLOSE)
      break;
    buf = recv_ssh_packet(timeout:timeout);
  }

  ssh_close_connection();

  show_ver = substr(show_ver, strlen(cmd));

  if ( show_ver =~ "Package\s*Release\s*Size\s*Description")
  {
    report += '\n' + 'Local security checks have been enabled for Alcatel Lucent.\n';
    set_kb_item(name:"Host/AOS/show_microcode", value:show_ver);
    security_note(port:0, extra:report);
    exit(0);
  }
}

# Handle Newer Alcatel Lucent Omini Switch Models
if (AOS_SSH || 'ERROR: Invalid entry: "cmd"' >< buf )
{
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  buf = ssh_cmd(cmd:'show microcode\r\nexit', nosudo:TRUE, nosh:TRUE, noexec:TRUE);
  ssh_close_connection();

  if ( buf =~ "Package\s*Release\s*Size\s*Description")
  {
    report += '\n' + 'Local security checks have been enabled for Alcatel Lucent.\n';
    set_kb_item(name:"Host/AOS/show_microcode", value:buf);
    security_note(port:0, extra:report);
    exit(0);
  }
}

if (SONICWALL_SSH == TRUE)
{
  buf = ssh_cmd(cmd:'show device', nosh:TRUE, nosetup:TRUE, noclose:TRUE, noexec:TRUE);

  # sonicwall v6 will return with no command message
  if (buf && "% No matching command found." >< buf)
  {
    buf = ssh_cmd(cmd:'show version', nosh:TRUE, nosetup:TRUE, noclose:TRUE, noexec:TRUE);
  }

  ssh_close_connection();

  if (!buf)
    exit(1, "Failed to determine SonicOS version.");

  # OS fingerprint info
  os_name = "SonicOS";
  up_time = "unknown";

  # sonicwall < 6
  if (buf && "Firmware Version: SonicOS" >< buf)
  {
    set_kb_item(name:"Host/SonicOS/show_device", value:buf);

    os_line = egrep(pattern:"^Firmware Version:", string:buf);
    if (os_line)
    {
      os_line = chomp(os_line);
      match = eregmatch(pattern:"^Firmware Version: SonicOS ((Enhanced|Standard) [0-9][^ ]+)", string:os_line);
      if (!isnull(match)) os_name += " " + match[1];
    }

    model_line = egrep(pattern:"^Model:", string:buf);
    if (model_line)
    {
      model_line = chomp(model_line);
      match = eregmatch(pattern:"^Model: (.+)", string:model_line);
      if (!isnull(match)) os_name += " on a SonicWALL " + match[1];
    }

    # Collect time of last reboot.
    if (buf && "Up Time:" >< buf)
    {
      foreach line (split(buf, keep:FALSE))
      {
        if (ereg(pattern:"^Up Time: [0-9]", string:line))
        {
          up_time = line;
          break;
        }
      }
    }
  }

  # sonicwall v6
  if (buf && 'firmware-version "SonicOS' >< buf)
  {
    set_kb_item(name:"Host/SonicOS/show_version", value:buf);

    os_line = egrep(pattern:'^firmware-version "', string:buf);
    if (os_line)
    {
      os_line = chomp(os_line);
      match = eregmatch(pattern:'^firmware-version "SonicOS ((Enhanced|Standard) [0-9][^"]+)', string:os_line);
      if (!isnull(match)) os_name += " " + match[1];
    }

    model_line = egrep(pattern:'^model "', string:buf);
    if (model_line)
    {
      model_line = chomp(model_line);
      match = eregmatch(pattern:'^model "(.+)"', string:model_line);
      if (!isnull(match)) os_name += " on a SonicWALL " + match[1];
    }

    # Collect time of last reboot.
    if (buf && 'system-uptime "' >< buf)
    {
      foreach line (split(buf, keep:FALSE))
      {
        if (ereg(pattern:'^system-uptime "', string:line))
        {
          up_time = line - 'system-uptime "' - '"';
          break;
        }
      }
    }
  }

  set_kb_item(name:"Host/OS/showver", value:os_name);
  set_kb_item(name:"Host/OS/showver/Confidence", value:100);
  set_kb_item(name:"Host/OS/showver/Type", value:"firewall");

  set_kb_item(name:"Host/last_reboot", value:up_time);

  report += '\n' +
    'Although local, credentialed checks for SonicOS are not available,\n' +
    'Nessus has managed to run commands in support of OS fingerprinting.\n' +
    '\n';
  security_note(port:0, extra:report);
  exit(0);
}
# nb: for some devices, we need to re-open the SSH connection
#     to run subsequent commands. We'll try to identify those
#     here based on the errors.
#
# ADTRAN
if (
  info_t == INFO_SSH &&
  !CISCO &&
  "RomSShell" >< ssh_banner &&
  '% Unrecognized command\r\n' >< buf
)
{
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  buf = ssh_cmd(cmd:"show version", nosh:TRUE, noexec:TRUE);
  if (buf && "ADTRAN, Inc." >< buf)
  {
    set_kb_item(name:"Host/ADTRAN/show_version", value:buf);

    # OS fingerprint info
    os_name = "ADTRAN Operating System";

    os_line = egrep(pattern:"^ADTRAN, Inc\. OS version", string:buf);
    if (os_line)
    {
      os_line = chomp(os_line);
      match = eregmatch(pattern:"^ADTRAN, Inc\. OS version ([A-Z0-9][0-9.]+)", string:os_line);
      if (!isnull(match)) os_name += " " + match[1];
    }

    type = "embedded";
    if ("Platform: NetVanta" >< buf) type = "router";

    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:type);

    # Collect time of last reboot.
    if (buf && " uptime is " >< buf)
    {
      foreach line (split(buf, keep:FALSE))
      {
        if (ereg(pattern:" uptime is [0-9]", string:line))
        {
          set_kb_item(name:"Host/last_reboot", value:line);
          break;
        }
      }
    }

    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

    buf = ssh_cmd(cmd:"exit", nosh:TRUE, noexec:TRUE);

    report += '\n' + 'Although local, credentialed checks for ADTRAN Operating System are' +
              '\n' + 'not available, Nessus has managed to run commands in support of OS' +
              '\n' + 'fingerprinting.' +
              '\n';
    security_note(port:0, extra:report);
    exit(0);
  }
}
# Blue Coat
if (
  info_t == INFO_SSH &&
  !CISCO &&
  "% Invalid input detected at '^' marker" >< buf
)
{
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  buf = ssh_cmd(cmd:"show version", nosudo:TRUE, nosh:TRUE, noexec:TRUE);

  if (buf && "Version: SGOS" >< buf)
  {
    set_kb_item(name:"Host/BlueCoat/ProxySG/show_version", value:buf);

    # OS fingerprint info
    os_name = "Blue Coat ProxySG";
    ui_line = egrep(pattern:"^UI Version:", string:buf);
    if (ui_line)
    {
      ui_line = chomp(ui_line);
      match = eregmatch(pattern:"^UI Version:( [0-9][0-9.]+) Build: ([0-9]+)", string:ui_line);
      if (!isnull(match)) os_name += match[1] + ' Build ' + match[2];
      else
      {
        match = eregmatch(pattern:"^UI Version:( [0-9].+)", string:ui_line);
        if (!isnull(match)) os_name += match[1];
      }
    }

    _local_checks_enabled();
    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"embedded");

    # Get 'show management-services' output; similar to a 'netstat -l'
    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

    buf = ssh_cmd(cmd:"show management-services", nosudo:TRUE, nosh:TRUE, noexec:TRUE);

    if (buf && "Service Name:" >< buf && "Service:" >< buf)
      set_kb_item(name:"Host/BlueCoat/ProxySG/show_management-services", value:buf);

    report += '\n' + 'Local security checks have been enabled for Blue Coat ProxySG.\n';
    security_note(port:0, extra:report);
    exit(0);
  }
}

# FireEye
else if (
  info_t == INFO_SSH &&
  !CISCO &&
  !buf &&
  '% Unrecognized command "cmd".\nType "?" for help' >< ssh_cmd_error()
)
{
  buf = ssh_cmd(cmd:"show version", nosh:TRUE, nosudo:TRUE, noexec:TRUE);
  if (buf && egrep(pattern:"^Product model:[ \t]+FireEye", string:buf))
  {
    set_kb_item(name:"Host/FireEye/show_version", value:buf);

    # OS fingerprint info
    os_name = "FireEye Operating System";

    pat = "^Product release:[ \t]+(.+)";
    line = egrep(pattern:pat, string:buf);
    if (line)
    {
      line = chomp(line);
      match = eregmatch(pattern:pat, string:line);
      if (!isnull(match)) os_name += ' ' + match[1];
    }

    pat = "^Product model:[ \t]+(FireEye[^ \t\r\n]+)";
    line = egrep(pattern:pat, string:buf);
    if (line)
    {
      line = chomp(line);
      match = eregmatch(pattern:pat, string:line);
      if (!isnull(match)) os_name += ' on a ' + match[1];
    }

    type = "firewall";

    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:type);

    # Collect time of last reboot.
    pat = "^Update:[ \t]+[0-9]";
    line = egrep(pattern:pat, string:buf);
    if (line)
    {
      line = chomp(line);
      match = eregmatch(pattern:pat, string:line);
      if (!isnull(match)) set_kb_item(name:"Host/last_reboot", value:line);
    }

    # Get running-config.
    #
    # nb: this requires running an 'enable' command first, then
    #     running a second command without closing the previous /
    #     setting up the new connection.
    cmd = "show running-config";
    buf = ssh_cmd(cmd:"enable", nosh:TRUE, nosudo:TRUE, noexec:TRUE, noclose:TRUE);
    buf = ssh_cmd(cmd:cmd, nosh:TRUE, nosudo:TRUE, noexec:TRUE, nosetup:TRUE);
    if (buf && egrep(pattern:"^[ \t]*license install", string:buf))
    {
      set_kb_item(name:"Secret/Host/FireEye/show_running_config", value:buf);
    }
    else
    {
      if (!buf) buf = ssh_cmd_error();
      cmd_prompt = get_kb_item("/tmp/ssh_cmd/cmd_prompt");
      if (isnull(cmd_prompt)) cmd_prompt = "";
      set_kb_item(name:"Host/FireEye/show_running_config/errmsg", value:cmd_prompt+cmd+'\r\n'+buf);
    }

    _local_checks_enabled();
    report += '\n' + 'Local security checks have been enabled for FireEye Operating System.\n';
    security_note(port:0, extra:report);
    exit(0);
  }
}
# Force10
else if (
  info_t == INFO_SSH &&
  "@force10networks.com" >< ssh_banner
)
{
  ssh_close_connection();
  sleep(1);
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  cmd = "show version";
  buf = ssh_cmd(cmd:cmd, nosh:TRUE, nosudo:TRUE, cisco:TRUE);

  if (
    !buf &&
    get_kb_item("Secret/SSH/enable-password") &&
    "password does not appear to be correct" >< ssh_cmd_error()
  )
  {
    report += '\n' + 'Note, though, that an attempt to elevate privileges using \'enable\' failed\n';
    errmsg = ssh_cmd_error();
    if (errmsg) report +='for the following reason :\n\n  - ' + errmsg + '\n\n';
    else report += 'for an unknown reason. ';
    report += 'Further commands will be run as the user';
    if (errmsg) report += ' ';
    else report += '\n';
    report += 'specified in the scan policy.\n';

    rm_kb_item(name:"Secret/SSH/enable-password");
    set_kb_item(name:"Host/Force10/enable-password-failure", value:TRUE);

    ssh_close_connection();
    sleep(1);
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

    buf = ssh_cmd(cmd:cmd, nosh:TRUE, nosudo:TRUE, cisco:TRUE);
  }

  if (buf && "Force10 Networks Real Time Operating System Software" >< buf)
  {
    set_kb_item(name:"Host/Force10/show_version", value:buf);

    # OS fingerprint info
    os = "Dell Force10 Operating System";
    os_line = egrep(pattern:"Force10 Application Software Version: ", string:buf);
    if (os_line)
    {
      os_line = chomp(os_line);
      match = eregmatch(pattern:"Force10 Application Software Version: +([0-9][0-9.]+)", string:os_line);
      if (!isnull(match)) os += " " + match[1];
    }

    set_kb_item(name:"Host/OS/showver", value:os);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"switch");

    ssh_close_connection();
    for (i=0; i<3; i++)
    {
      sleep(i+1);
      sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
      if (sock_g) break;
      ssh_close_connection();
    }
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

    cmd = 'show running-config';
    buf = ssh_cmd(cmd:cmd, nosh:TRUE, nosudo:TRUE, cisco:TRUE);

    if (!isnull(buf) && !egrep(pattern:"^(Current Configuration|interface )", string:buf))
    {
      if ('^\r\n% ' >< buf)
      {
        i = stridx(buf, '^\r\n% ');

        # nb: make sure the error marker appears either at the start or
        #     after a series of spaces.
        if (i == 0 || (i > 0 && ereg(pattern:"^ +$", string:substr(buf, 0, i-1))))
        {
          cmd_prompt = get_kb_item("/tmp/ssh_cmd/cmd_prompt");
          if (isnull(cmd_prompt)) cmd_prompt = "";
          set_kb_item(name:"Host/Force10/show_running_config/errmsg", value:cmd_prompt+cmd+'\r\n'+buf);
        }
      }
      buf = NULL;
    }
    else if (buf) set_kb_item(name:"Host/Force10/show_running_config", value:buf);

    report += '\n' + 'Although local, credentialed checks for Dell Force10 are not' +
              '\n' + 'available, Nessus has managed to run commands in support of OS' +
              '\n' + 'fingerprinting.' +
              '\n';
    security_note(port:0, extra:report);
    exit(0);
  }
  else exit(1, "Unknown Force10 behavior.");
}
# HP (formerly ProCurve) switches
# The connection must be reset after each command
else if (
  info_t == INFO_SSH &&
  !CISCO &&
  (
    (
      !buf &&
      (
        "% Unrecognized command found at '^' position" >< ssh_cmd_error() ||
        "SSH command execution is not supported." >< ssh_cmd_error()
      )
    ) ||
    ("Invalid input: cmd" >< buf)
  )
)
{
  # HP has a convenient command that will catch everything we want in one go
  # We will try the 'show tech' cmd first then if it fails try the rest.
  cmd = "show tech";

  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  buf_tech = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, last5_prompt:'#');
  if ( ( "show system" >< buf_tech ) && ( "procurve" >< tolower(buf_tech) ) )
  {
    os_name = "HP Switch";

    match = eregmatch(pattern:"Software revision[ \t]*:[ \t]*([^ \n\r]+)", string:buf_tech);
    if (!isnull(match)) os_name += " with software revision " + match[1];

    set_kb_item(name:"Host/HP_Switch/show_tech", value:buf_tech);

    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"switch");

    set_kb_item(name:"Host/HP_Switch", value:TRUE);

    _local_checks_enabled();
    report += '\n' + 'Local security checks have been enabled for HP Switches.\n';
    security_note(port:0, extra:report);
    exit(0);
  }
  else
  {
    if ("% Unrecognized command found at '^' position" >< ssh_cmd_error()) cmd = "summary";
    else cmd = "show module details";

    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

    buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE);

    if ("Invalid input: details" >< buf && "show module" >< cmd)
    {
      ssh_close_connection();
      sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
      buf = ssh_cmd(cmd:"show modules", nosudo:TRUE, nosh:TRUE, noexec:TRUE);
    }

    if (
      buf &&
      (
        ("summary" >< cmd && "Comware Software, Version " >< buf) ||
        ("show module" >< cmd && "Chassis: " >< buf)
      )
    )
    {
      # OS fingerprint info
      os_name = "HP Switch";

      if ("summary" >< cmd)
      {
        match = eregmatch(pattern:"HP ([^ ]+) Switch", string:buf);
        if (!isnull(match)) os_name = "HP " + match[1] + " Switch";

        match = eregmatch(pattern:"Comware Software, Version ([0-9][0-9.]+) Release ([^ ]+)", string:buf);
        if (!isnull(match)) os_name += " with Comware software version " + match[1] + " release " + match[2];

        foreach line (split(buf, keep:FALSE))
        {
          if (ereg(pattern:"^HP [^ ]+ Switch uptime is ", string:line))
          {
            set_kb_item(name:"Host/last_reboot", value:line);
            break;
          }
        }

        # local check info
        set_kb_item(name:"Host/HP_Switch/summary", value:buf);
      }
      else
      {
        match = eregmatch(pattern:"Chassis:[ \t]*([^ ]+) *([^ ]+)", string:buf);
        if (!isnull(match)) os_name = "HP " + match[1] + " Switch (" + match[2] + ")";

        set_kb_item(name:"Host/HP_Switch/show_modules", value:buf);

        ssh_close_connection();
        sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
        if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
        cmd2 = 'show system';
        buf2 = ssh_cmd(cmd:cmd2, nosudo:TRUE, nosh:TRUE, noexec:TRUE);
        if (buf2 && "Software revision" >< buf2)
        {
          match = eregmatch(pattern:"Software revision[ \t]*:[ \t]*([^ \n\r]+)", string:buf2);
          if (!isnull(match)) os_name += " with software revision " + match[1];

          # local check info
          set_kb_item(name:"Host/HP_Switch/show_system", value:buf2);
        }

        # Get time of last reboot.
        ssh_close_connection();
        sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
        if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
        cmd3 = 'show uptime';
        buf3 = ssh_cmd(cmd:cmd3, nosudo:TRUE, nosh:TRUE, noexec:TRUE);

        if (buf3) set_kb_item(name:"Host/last_reboot", value:buf3);

        ssh_close_connection();
        sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
        if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
        cmd4 = 'show ver';
        buf4 = ssh_cmd(cmd:cmd4, nosudo:TRUE, nosh:TRUE, noexec:TRUE);

        if (buf4) set_kb_item(name:"Host/HP_Switch/show_ver", value:buf4);
      }

      set_kb_item(name:"Host/OS/showver", value:os_name);
      set_kb_item(name:"Host/OS/showver/Confidence", value:100);
      set_kb_item(name:"Host/OS/showver/Type", value:"switch");

      set_kb_item(name:"Host/HP_Switch", value:TRUE);

      _local_checks_enabled();
      report += '\n' + 'Local security checks have been enabled for HP Switches.\n';
      security_note(port:0, extra:report);
      exit(0);
    }
  }
}
# BIG-IP Device with only TMSH access
else if (
  info_t == INFO_SSH &&
  !CISCO             &&
  'Syntax Error: unexpected argument "cmd"' >< buf
)
{
  buf = ssh_cmd(cmd:"show sys version",nosudo:TRUE,nosh:TRUE,noexec:TRUE);
  ver = eregmatch(string:buf, pattern:"[Vv]ersion[ \t]*([0-9.]+)($|[^0-9.])");
  if(!isnull(buf) && "BIG-IP" >< buf && !isnull(ver))
  {
    ver = ver[1];
    set_kb_item(name:"Host/OS/showver", value:"F5 Networks BIG-IP "+ver);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"load-balancer");
    set_kb_item(name:"Host/BIG-IP/version",value:ver);
    # Needed for extra parsing
    set_kb_item(name:"Host/BIG-IP/raw_showver",value:buf);
    buf = ssh_cmd(cmd:"list /sys provision",nosudo:TRUE,nosh:TRUE,noexec:TRUE);
    if(buf)
    {
      _local_checks_enabled();
      set_kb_item(name:'Host/BIG-IP/raw_modules', value:buf);
      report += '\n' + 'Local security checks have been enabled for F5 Networks BIG-IP.' +
                '\n';
    }
    else
    {
      report += '\n' + 'Nessus is unable to perform local, credentialed checks for F5 Networks' +
                '\n' + 'BIG-IP because the account provided is not privileged enough to run'+
                '\n' + 'commands required for these checks.'+
                '\n';
    }
    security_note(port:0, extra:report);
    exit(0);
  }
}
# Juniper ERX / A10 Networks ACOS
else if (
  info_t == INFO_SSH &&
  !CISCO &&
  "% Unrecognized command" >< buf
)
{
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  buf = ssh_cmd(cmd:"show version", nosudo:TRUE, nosh:TRUE, noexec:TRUE);

  if (buf && "Juniper Edge Routing Switch" >< buf && "Version:" >< buf)
  {
    os = "JunosE";

    set_kb_item(name:"Host/JunosE/show_version", value:buf);

    item = eregmatch(pattern:"Version: ([^[]+\[[^]]+\])", string:buf);
    if (!isnull(item))
    {
      os += ' ' + item[1];
      set_kb_item(name:'Host/JunosE/version', value:item[1]);
    }

    set_kb_item(name:"Host/OS/showver", value:os);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"switch");

    item = eregmatch(pattern:"Juniper Edge Routing Switch (E[^ \r\n]+)", string:buf);
    if (!isnull(item)) set_kb_item(name:'Host/JunosE/platform', value:item[1]);

    _local_checks_enabled();
    report += '\n' + 'Local security checks have been enabled for JunosE.\n';
    security_note(port:0, extra:report);
    exit(0);
  }
  else if (buf && "Advanced Core OS (ACOS)" >< buf && "A10 Networks" >< buf)
  {
    item = eregmatch(pattern:"\(ACOS\) version ([^, ]+), build ([0-9]+)[^0-9]",
                     string:buf);

    if (!isnull(item) && !isnull(item[1]) && !isnull(item[2]))
    {
      os = "A10 Networks Advanced Core OS";
      set_kb_item(name:"Host/A10_ACOS/show_version", value:buf);

      os += ' ' + item[1] + ' build ' + item[2];
      set_kb_item(name:'Host/A10_ACOS/version', value:item[1]);
      set_kb_item(name:'Host/A10_ACOS/build', value:item[2]);
      replace_kb_item(name:"A10/ACOS", value:TRUE);

      # series and device should be on first line of show ver output
      # e.g.
      # Thunder Series Unified Application Service Gateway vThunder
      # AX Series Advanced Traffic Manager AX1000
      # AX Series Advanced Traffic Manager AXSoftAX
      lines = split(buf, sep:'\n', keep:FALSE);
      item = eregmatch(pattern:"^([^ ]+) Series .* ([^\t ]+)[\t ]*$", string:lines[0]);
      if(!isnull(item) && !isnull(item[1]) && !isnull(item[2]))
      {
        set_kb_item(name:'Host/A10_ACOS/series', value:item[1]);
        set_kb_item(name:'Host/A10_ACOS/device', value:item[2]);
      }

      set_kb_item(name:"Host/OS/showver", value:os);
      set_kb_item(name:"Host/OS/showver/Confidence", value:100);
      set_kb_item(name:"Host/OS/showver/Type", value:"load-balancer");

      _local_checks_enabled();
      report += '\nLocal security checks have been enabled for A10 Networks Advanced Core OS.\n';
      security_note(port:0, extra:report);
      exit(0);
    }
  }
}
# NetApp Data ONTAP
else if (
  info_t == INFO_SSH &&
  !CISCO &&
  !buf &&
  ( 
    "not found.  Type '?' for a list of commands" >< ssh_cmd_error() ||
    "Error: Ambiguous command." >< ssh_cmd_error() ||
    ("Error:" >< ssh_cmd_error() && "is not a recognized command" >< ssh_cmd_error())
  )
)
{
  if( "Error: Ambiguous command." >< ssh_cmd_error() ||
      (
        "Error:" >< ssh_cmd_error() && "is not a recognized command" >< ssh_cmd_error()
      )
    ) 
      clustered = TRUE;
  else clustered = FALSE;
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
  # nb: NetApp seems to need a pause before sending commands,
  #     otherwise 'ssh_cmd()' fails sporadically.
  sleep(1);

  if(clustered)
  { 
    buf = ssh_cmd(cmd:"system node run -node local sysconfig -a", nosudo:TRUE, nosh:TRUE, noexec:TRUE);
  }
  else 
    buf = ssh_cmd(cmd:"version", nosudo:TRUE, nosh:TRUE, noexec:TRUE);

  if (buf && "NetApp Release" >< buf)
  {
    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
    sleep(1);

    if(clustered)
    {
      uptime = ssh_cmd(cmd:"system node show -node local", nosudo:TRUE, nosh:TRUE, noexec:TRUE);
      uptime = eregmatch(pattern:"Uptime:\s+([^\r\n]+)", string: uptime);
      if (uptime) set_kb_item(name:"Host/last_reboot", value:uptime[1]);
    }
    else
    {
      uptime = ssh_cmd(cmd:"uptime", nosh:TRUE);
      if (uptime) set_kb_item(name:"Host/last_reboot", value:uptime);
    }

    # OS fingerprint info
    os_name = "NetApp";
    match = eregmatch(pattern:"^\s*(NetApp Release [0-9][^:]+)", string:buf);
    if (!isnull(match)) os_name = match[1];

    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"embedded");

    report += '\n' + 'Local security checks have NOT been enabled for NetApp Data ONTAP.\n';
    security_note(port:0, extra:report);
    exit(0);
  }
}
# Riverbed Optimization System (RiOS)
else if (
  info_t == INFO_SSH &&
  !CISCO &&
  !buf &&
  ('% Unrecognized command "cmd /C ver".\r\nType "?" for help' >< ssh_cmd_error() ||
   '% Unrecognized command "cmd".\r\nType "?" for help' >< ssh_cmd_error() )
)
{
  cmd = "show version";
  buf = ssh_cmd(cmd:cmd, nosh:TRUE, nosudo:TRUE, cisco:TRUE);
  if (buf && egrep(pattern:"Product name:[ \t]+rbt", string:buf))
  {
    set_kb_item(name:"Host/Riverbed/show_version", value:buf);

    # OS fingerprint info
    os_name = "Riverbed Optimization System (RiOS)";

    pat = "^Product release:[ \t]+(.+)";
    line = egrep(pattern:pat, string:buf);
    if (line)
    {
      line = chomp(line);
      match = eregmatch(pattern:pat, string:line);
      if (!isnull(match)) os_name += ' ' + match[1];
    }

    pat = "^Product model:[ \t]+([^ \t\r\n]+)";
    line = egrep(pattern:pat, string:buf);
    if (line)
    {
      line = chomp(line);
      match = eregmatch(pattern:pat, string:line);
      if (!isnull(match)) os_name += ' on a ' + match[1];
    }

    report += '\n' + 'The remote operating system is : ' + os_name +
              '\n';

    type = "embedded";

    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:type);

    # Collect time of last reboot.
    pat = "^Uptime:[ \t]+[0-9]";
    line = egrep(pattern:pat, string:buf);
    if (line)
    {
      line = chomp(line);
      match = eregmatch(pattern:pat, string:line);
      if (!isnull(match)) set_kb_item(name:"Host/last_reboot", value:line);
    }

    report += '\n' + 'Although local, credentialed checks for Riverbed Optimization System' +
              '\n' + '(RiOS) are not available, Nessus has managed to run commands in' +
              '\n' + 'support of OS fingerprinting.' +
              '\n';
    security_note(port:0, extra:report);
    exit(0);
  }
  else if (!buf && "Riverbed ssh: ssh remote command is not allowed" >< ssh_cmd_error())
  {
    msg = "Execution of the command '"+cmd+"' failed.";
    error_msg = ssh_cmd_error();
    if (error_msg) msg += '\n' + error_msg;
    # nb: we don't support local checks for RiOS currently so don't
    #     report failures in hostlevel_check_failed.nasl.
    # set_kb_item(name:'HostLevelChecks/failure', value:msg);
    exit(1, msg);
  }
}
# ScreenOS
else if (
  info_t == INFO_SSH &&
  !CISCO &&
  (
    "-NetScreen" >< ssh_banner ||
    "^------unknown keyword cmd" >< buf
  )
)
{
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  buf = ssh_cmd(cmd:"get system", nosudo:TRUE, nosh:TRUE, noexec:TRUE);
  if (
    buf &&
    (
      "File Name: screenos_image, Checksum: " >< buf ||
      egrep(pattern:"^Hardware Version: .+, FPGA checksum", string:buf)
    )
  )
  {
    set_kb_item(name:"Host/Juniper/ScreenOS/get_system", value:buf);

    # OS fingerprint info
    os_name = "Juniper ScreenOS";
    type = "firewall";

    line = egrep(pattern:"^Software Version: ([0-9][^, ]+),", string:buf);
    if (line)
    {
      line = chomp(line);
      match = eregmatch(pattern:"^Software Version: ([0-9][^, ]+),", string:line);
      if (!isnull(match)) os_name += " " + match[1];
    }

    _local_checks_enabled();
    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:type);

    # Get uptime info.
    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

    cmd = 'get clock';
    buf = ssh_cmd(cmd:cmd, nosh:TRUE, nosudo:TRUE, noexec:TRUE);
    if (buf)
    {
      line = egrep(pattern:"^Up [0-9]+ .+ Since ", string:buf);
      if (line)
      {
        line = chomp(line);
        set_kb_item(name:"Host/last_reboot", value:line);
      }
    }

    report += '\n' + 'Local security checks have been enabled for Juniper ScreenOS.\n';
    security_note(port:0, extra:report);
    exit(0);
  }
}
# Trend Micro IWSVA
else if (
  info_t == INFO_SSH &&
  !CISCO &&
  "diagnose     Diagnose the environment" >< buf
)
{
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  buf = ssh_cmd(cmd:"show system version", nosudo:TRUE, nosh:TRUE, noexec:TRUE);
  if (isnull(buf)) buf = ssh_cmd(cmd:"show version", nosudo:TRUE, nosh:TRUE, noexec:TRUE);
  if (buf && "IWSVA: " >< buf)
  {
    set_kb_item(name:"Host/TrendMicro/IWSVA/show_system_version", value:buf);

    # OS fingerprint info
    os_name = "IWSVA";
    type = "firewall";

    line = pgrep(pattern:"^IWSVA: IWSVA ([0-9][^, ]+),", string:buf);
    if (line)
    {
      line = chomp(line);
      match = pregmatch(pattern:"IWSVA: (IWSVA [0-9.]+(?:-SP\d+)?_[Bb]uild_(?:[Ll]inux_)?[0-9]+)($|[^0-9])", string:line);
      if (!isnull(match)) os_name += " " + match[1];
    }

    _local_checks_enabled();
    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:type);

    # Get uptime info.
    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

    cmd = 'show system uptime';
    buf = ssh_cmd(cmd:cmd, nosh:TRUE, nosudo:TRUE, noexec:TRUE);
    if (buf)
    {
      line = egrep(pattern:"^[0-9:]+ up [0-9]+ .+", string:buf);
      if (line)
      {
        line = chomp(line);
        set_kb_item(name:"Host/last_reboot", value:line);
      }
    }

    report += '\n' + 'Local security checks have been enabled for Trend Micro IWSVA.\n';
    security_note(port:0, extra:report);
    exit(0);
  }
}
# - Cisco Unified IP Phone running CNU-OS
# - The IP phone implements a second-stage authentication conducted over a SSH channel.
#   Commands cannot be run until this authentication succeeds.
# - Note that the sshd on the device return a version string "SSH-2.0-1.00" that
#   doesn't contains text 'Cisco', thus the CISCO variable is not set.
# - The command 'cmd /C ver' last sent was interpreted by the phone as the login name, so it
#   responds with a password prompt.
else if (
  info_t == INFO_SSH &&
  !CISCO &&
  "password:" >< buf
)
{
  # close and reconnect
  ssh_close_connection();

  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  local_var login, pass, cmd;

  login = "debug";
  pass  = "debug";
  cmd   = "show version";

  # login with debug/debug and run a command
  # NOTE: the 'show version' command is only available when logged in as debug
  buf = ssh_cmd(cmd:login+'\n'+ pass+ '\n' + cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE);

  # sample output:
  #
  # 0x00:  64 65 62 75 67 0A 0D 70 61 73 73 77 6F 72 64 3A    debug..password:
  # 0x10:  20 0A 0D 0A 0D 0A 0D 46 30 32 39 32 39 35 38 30     ......F02929580
  # 0x20:  33 31 44 3E 20 73 68 6F 77 20 76 65 72 73 69 6F    31D> show versio
  # 0x30:  6E 0A 0D 43 4E 55 36 2D 4F 53 20 20 39 2E 30 28    n..CNU6-OS  9.0(
  # 0x40:  32 45 53 33 2E 29 20 34 2E 31 28 30 2E 31 29 20    2ES3.) 4.1(0.1)
  # 0x50:  43 50 2D 37 39 34 32 47 20 50 53 59 4C 20 30 30    CP-7942G PSYL 00
  # 0x60:  32 30 2D 31 32 28 4D 49 50 53 33 32 29 0A 0D 0A    20-12(MIPS32)...
  # 0x70:  0D 46 30 32 39 32 39 35 38 30 33 31 44 3E          .F0292958031D>
  #
  # Note that:
  # 1) user name and the command are echoed back
  # 2) '\n\r' (as opposed to '\r\n') are used to separate lines
  # 3) command prompt consists of device's MAC address followed by a '>'
  if (buf &&
      login >< buf &&
      cmd >< buf &&
      'password:'   >< buf &&  # password prompt sent by server
      (cnu_os = egrep(string:buf, pattern:"CNU[^ ]+OS.+"))
    )
    {
      set_kb_item(name:"Host/Cisco/CNU-OS", value:cnu_os);

      # OS fingerprint info
      set_kb_item(name:"Host/OS/showver", value:cnu_os);
      set_kb_item(name:"Host/OS/showver/Confidence", value:95);
      set_kb_item(name:"Host/OS/showver/Type", value:"embedded");

      _local_checks_enabled();
      report += '\n' + 'Local security checks have been enabled for Cisco CNU-OS.\n';
      security_note(port:0, extra:report);
      exit(0);
   }
}
# Palo Alto PAN-OS
else if (
  (info_t == INFO_SSH           &&
   !CISCO                       &&
  "Unknown command: cmd" >< buf)
  ||
  SSH_GET_INFO_PANOS_BUGGED
)
{
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  cmd = "show system info | match *";
  buf = ssh_cmd(cmd:cmd, noexec:TRUE, nosh:TRUE, nosudo:TRUE, no53:SSH_GET_INFO_PANOS_BUGGED, last5_prompt:">");

  if(buf !~ "model: ((PA|pa|VM|vm)-|Panorama)")
  {
    # Newer versions  of PANOS (6+) have a bug with match
    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
    cmd = "show system info";
    buf = ssh_cmd(cmd:cmd, noexec:TRUE, nosh:TRUE, nosudo:TRUE, no53:SSH_GET_INFO_PANOS_BUGGED, last5_prompt:">");
  }

  # Verify that we are looking at a Palo Alto device.
  if (buf =~ "model: ((PA|pa|VM|vm)-|Panorama)")
  {
    set_kb_item(name:"Host/Palo_Alto/show_system_info", value:buf);

    # OS Fingerprint info.
    os = "PAN-OS";
    pat = "sw-version: ([0-9.]+(?:-[Hh][0-9]+)?)";
    match = eregmatch(string:buf, pattern:pat, icase:TRUE);
    if (!isnull(match)) os += ' ' + match[1];

    report += '\n' + 'The remote Palo Alto system is : ' + os +
              '\n';

    set_kb_item(name:"Host/OS/showver", value:os);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"firewall");

    _local_checks_enabled();

    report += '\n' + 'Local security checks have been enabled for this host.' +
              '\n';
    security_note(port:0, extra:report);
    exit(0);
  }
}
# Cisco Wireless LAN Controllers
else if (
  info_t == INFO_SSH &&
  !CISCO &&
  (
    !buf
    ||
    "Incorrect usage. Use the " >< buf
  )
)
{
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:FALSE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  cmd = "show sysinfo";
  buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, nosetup:TRUE);

  # verify that we are working with a WLC system
  if (buf && egrep(pattern:"Product Name.+Cisco Controller", string:buf))
  {
    set_kb_item(name:"Host/Cisco/WLC", value:TRUE);
    set_kb_item(name:"Host/Cisco/show_ver", value:buf);

    # OS fingerprint info
    os_name = "Cisco Wireless LAN Controller";
    match = eregmatch(pattern:"Product Version.+ ([0-9][0-9.]+)", string:buf);
    if (!isnull(match)) os_name += " release " + match[1];

    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"wireless-access-point");

    # Uptime.
    match = eregmatch(pattern:"System Up Time.+ ([0-9].+)", string:buf);
    if (!isnull(match)) set_kb_item(name:"Host/last_reboot", value:match[1]);

    #show inv
    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

    cmd = 'show inventory';
    buf2 = ssh_cmd(cmd:cmd, nosh:TRUE, nosetup:TRUE);
    if (buf2) set_kb_item(name:"Host/Cisco/show_inventory", value:buf2);

    #show running
    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

    cmd = 'show run-config';
    buf2 = ssh_cmd(cmd:cmd, nosh:TRUE, nosetup:TRUE);
    if (buf2) set_kb_item(name:"Secret/Host/Cisco/show_running", value:buf2);

    _local_checks_enabled();
    report += '\n' + 'Local security checks have been enabled for Cisco Wireless LAN Controllers.\n';
    security_note(port:0, extra:report);
    exit(0);
  }

  # Try to test for FortiOS.
  # FortiOS devices will not accept further ssh_cmd without resetting
  # the connection.
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  cmd = 'get system status';
  buf = ssh_cmd(cmd:cmd, nosh:TRUE, nosudo:TRUE, noexec:TRUE);

  if (buf && "Forti" >< buf)
  {
    # We use 'Fortigate' as the KB key for compatibility reasons with
    # the compliance plugins. However, this should be covering all
    # devices that run FortiOS, not just Fortigate.
    set_kb_item(name:"Host/Fortigate/get_system_status", value:buf);

    # Get Platform data if available.
    platform = NULL;
    if ("Platform Full Name" >< buf)
    {
      pattern = "Platform Full Name\s*:\s*(Forti\w+-[\d\w]+)";
      match = eregmatch(string:buf, pattern:pattern);
      if (!isnull(match)) platform = match[1];
    }

    # Get version/model info.
    pattern = "Version\s*?:\s*(Forti\w+(-[\d\w]+)+)?\s+v?((?:\d+\.)*\d+[, -]build\d+[, ]\d+(?:\s+\([\d\w]+ Patch \d+\))?)";
    match = eregmatch(string:buf, pattern:pattern);
    if (isnull(match)) exit(1, "Failed to parse 'get system status' from Fortinet device.");

    # Populate model/platform.
    if (!isnull(platform)) model = platform;
    else if (match[1]) model = match[1];
    else model = "Unknown Fortinet Device";

    # Populate version.
    if (match[3]) version = match[3];
    else version = "Unknown Version";

    os = "FortiOS " + version + " on " + model;

    set_kb_item(name:"Host/Fortigate/model", value:model);

    # Set OS KB's.
    set_kb_item(name:"Host/OS/showver", value:os);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"firewall");

    # Get performance data.
    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

    cmd = 'get system performance status';
    buf = ssh_cmd(cmd:cmd, nosh:TRUE, nosudo:TRUE, noexec:TRUE);

    if (buf && "Uptime" >< buf)
      set_kb_item(name:"Host/Fortigate/get_system_performance_status", value:buf);

    _local_checks_enabled();
    report += '\nLocal security checks have been enabled for FortiOS on Fortinet devices.\n';

    security_note(port:0, extra:report);
    exit(0);
  }
}
# Cisco RHEL or ADE-OS based systems
else if(
  info_t == INFO_SSH &&
  "OpenSSH" >< ssh_banner && # RHEL 5 Based system
  "% invalid command detected at '^' marker" >< buf
)
{
  buf = ssh_cmd(cmd:'show ver', nosudo:TRUE, nosh:TRUE, cisco:TRUE, noclose:TRUE);
  ssh_cmd(cmd:'exit', nosudo:TRUE, nosh:TRUE, cisco:TRUE, nosetup:TRUE);
  ssh_close_connection();

  found_ade_os_app = FALSE;

  # Check for Prime Collaboration
  if(
    !isnull(buf) &&
    "Version information of installed applications" >< buf &&
    "Cisco Prime Collaboration Assurance" >< buf
  )
  {
    match = eregmatch(string:buf, pattern:'Cisco Prime Collaboration Assurance\r?\n-+\r?\nVersion[ \t]+: ([0-9.]+)\r?\n');
    if(!isnull(match))
    {
      set_kb_item(name:"Host/Cisco/PrimeCollaborationAssurance", value:TRUE);
      set_kb_item(name:"Host/Cisco/PrimeCollaborationAssurance/show_ver", value:buf);
      set_kb_item(name:"Host/Cisco/PrimeCollaborationAssurance/version", value:match[1]);
      set_kb_item(name:"Host/OS/showver", value:"Cisco Prime Collaboration Assurance "+match[1]);
      set_kb_item(name:"Host/OS/showver/Confidence", value:100);
      set_kb_item(name:"Host/OS/showver/Type", value:"embedded");
      _local_checks_enabled();
      report += '\n' + 'Local security checks have been enabled for Cisco Prime Collaboration Assurance.\n';
      found_ade_os_app = TRUE;
    }
  }

  if(
    !isnull(buf) &&
    "Version information of installed applications" >< buf &&
    ("Cisco Prime Collaboration Provisioning" >< buf ||
    "Collaboration Manager" >< buf)
  )
  {
    match = eregmatch(string:buf, pattern:'Collaboration (Provisioning|Manager)\r?\n-+\r?\nVersion[ \t]+: ([0-9.]+)\r?\n');
    if(!isnull(match))
    {
      set_kb_item(name:"Host/Cisco/PrimeCollaborationProvisioning", value:TRUE);
      set_kb_item(name:"Host/Cisco/PrimeCollaborationProvisioning/show_ver", value:buf);
      set_kb_item(name:"Host/Cisco/PrimeCollaborationProvisioning/version", value:match[2]);
      set_kb_item(name:"Host/OS/showver", value:"Cisco Prime Collaboration Provisioning "+match[2]);
      set_kb_item(name:"Host/OS/showver/Confidence", value:100);
      set_kb_item(name:"Host/OS/showver/Type", value:"embedded");
      _local_checks_enabled();
      report += '\n' + 'Local security checks have been enabled for Cisco Prime Collaboration Assurance.\n';
      found_ade_os_app = TRUE;
    }
  }

  if (
    !isnull(buf) &&
    "Cisco Identity Services Engine" >< buf &&
    "Version information of installed applications" >< buf
  )
  {
    match = pregmatch(string:buf,
      pattern:'Cisco Identity Services Engine(?: Express)?[ \r\n]+-+\r?\nVersion[ \t]+: ([0-9.]+)\r?\n');
    if (!isnull(match))
    {
      set_kb_item(name:"Host/Cisco/ISE", value:TRUE);
      set_kb_item(name:"Host/Cisco/ISE/version", value:match[1]);
      set_kb_item(name:"Host/Cisco/show_ver", value:buf);
      set_kb_item(name:"Host/OS/showver", value:"Cisco Identity Services Engine " + match[1]);
      set_kb_item(name:"Host/OS/showver/Confidence", value:100);
      set_kb_item(name:"Host/OS/showver/Type", value:"embedded");
      _local_checks_enabled();
      report += '\n' + 'Local security checks have been enabled for Cisco Identity Services Engine.\n';
      found_ade_os_app = TRUE;
    }
  }

  # Cisco Cloud Services Platform (CSP)
  found_csp_app = FALSE;
  if (
    !found_ade_os_app &&
    !isnull(buf) &&
    "Cisco Cloud Services Platform Software," >< buf &&
    "Red Hat Enterprise Linux" >< buf
  )
  {
    # Cisco Cloud Services Platform Software, 2100 Software (CSP-2100), Version 2.0.0 Build:6
    pattern =
      "Cisco Cloud Services Platform Software, [0-9]+ Software \(CSP-([0-9]+)\), Version ([0-9.]+) Build:([0-9]+)";
    match = eregmatch(string:buf, pattern:pattern);
    if (!isnull(match))
    {
      set_kb_item(name:"Host/Cisco/CloudServicesPlatform", value:TRUE);
      set_kb_item(name:"Host/Cisco/CloudServicesPlatform/show_ver", value:buf);
      set_kb_item(name:"Host/Cisco/CloudServicesPlatform/version", value:match[2]);
      set_kb_item(name:"Host/Cisco/CloudServicesPlatform/build", value:match[3]);
      set_kb_item(name:"Host/Cisco/CloudServicesPlatform/model", value:match[1]);

      set_kb_item(name:"Host/OS/showver", value:"Cisco Cloud Services Platform "+match[2] + " Build " + match[3]);
      set_kb_item(name:"Host/OS/showver/Confidence", value:100);
      set_kb_item(name:"Host/OS/showver/Type", value:"embedded");
      _local_checks_enabled();
      report += '\n' + 'Local security checks have been enabled for Cisco Cloud Services Platform.\n';
      found_csp_app = TRUE;
    }
  }

  if("ADE-OS Build Version" >< buf && !found_ade_os_app)
    report += '\nHowever, the Cisco ADE-OS based system is unknown to Nessus.\n';
  else if(!found_ade_os_app && !found_csp_app)
    report += '\nHowever, the system is unknown to Nessus.\n';

  security_note(port:0, extra:report);
  exit(0);
}
# Cisco UCS Integrated Management Control (CIMC)
else if(
  info_t == INFO_SSH  &&
  "-dropbear" >< ssh_banner &&
  "% invalid command detected at '^' marker" >< buf
)
{
  # Run show cimc command to confirm we are on the system we think we are
  # Firmware version will be in the form 1.0(1b) or 1.0(1) or 1.0(0.86b) ect
  buf = ssh_cmd(cmd:"show cimc", nosh:TRUE, nosudo:TRUE, cisco:FALSE, noexec:TRUE);
  if (buf) match = eregmatch(string:buf, pattern:'\n'+"(\d+\.\d+\([0-9.]+[A-Za-z]?\))\s+");
  else match = NULL;

  if (!isnull(match))
  {
    cimcver = match[1];
    set_kb_item(name:"Host/Cisco/CIMC", value:TRUE);
    set_kb_item(name:"Host/Cisco/CIMC/show_cimc", value:buf);
    set_kb_item(name:"Host/Cisco/CIMC/version", value:cimcver);

    set_kb_item(name:"Host/OS/showver", value:"Cisco Integrated Management Controller "+cimcver);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"embedded");
  }

  _local_checks_enabled();
  report += '\n' + 'Local security checks have been enabled for Cisco Integrated Management Controller.\n';
  security_note(port:0, extra:report);

  # try show chassis for more detail
  buf2 = ssh_cmd(cmd:"show chassis", nosh:TRUE, nosudo:TRUE, cisco:FALSE, noexec:TRUE);

  # Sanity check and check for known headers of show chassis output
  if ("% invalid command detected at '^' marker" >!< buf2 &&
  "PID" >< buf2 && "UUID" >< buf2 && "Product Name" >< buf2)
  {
    set_kb_item(name:"Host/Cisco/CIMC/show_chassis", value:buf2);
  }
  exit(0);
}
# Cisco Unity Connection
else if ("Executed command unsuccessfully" >< buf)
{
  os_name = NULL;
  # Try to see if Unity Connection is installed
  cmd = "show tech ccm_service";
  buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:FALSE, noexec:TRUE);
  if ("GroupName: Unity Connection Services" >< buf)
  {
    os_name      = "Cisco Unity Connection";
    kb_item_os   = "Host/Cisco/CUC";
    kb_item_info = "Unity_Connection";
  }
  else if ("GroupName: CM Services" >< buf)
  {
    os_name      = "Cisco Unified Communications Manager";
    kb_item_os   = "Host/Cisco/CUCM";
    kb_item_info = "CUCM";
  }

  if (!isnull(os_name))
  {
    set_kb_item(name:kb_item_os, value:TRUE);

    cmd = "show version active";
    buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:FALSE, noexec:TRUE);
    if (buf)
      set_kb_item(name:"Host/Cisco/" + kb_item_info + "/show_version_active", value:buf);

    # OS fingerprint info
    if (buf)
    {
      match = eregmatch(string:buf, pattern:"Version:\s+([0-9.-]+)");
      if (!isnull(match))
      {
        os_name += " " + match[1];
        version = str_replace(string:match[1], find:"-", replace:".");
        replace_kb_item(name:"Host/Cisco/" + kb_item_info + "/Version", value:version);
        replace_kb_item(name:"Host/Cisco/" + kb_item_info + "/Version_Display", value:match[1]);
      }
    }
    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"embedded");

    _local_checks_enabled();
    report += '\n' + 'Local security checks have been enabled for ' + os_name + '.\n';
    security_note(port:0, extra:report);
    exit(0);
  }
}
# Huawei Versatile Routing Platform
else if ("Unrecognized command found at '^' position." >< buf && "DOPRA" >< ssh_banner)
{
  # Reset SSH connection.
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  # Get version information.
  buf = ssh_cmd(cmd:"display version", nosh:TRUE, noexec:TRUE);

  if (buf && "Huawei Versatile" >< buf)
  {
    # Save buffer for platform-specific plugin.
    set_kb_item(name:"Host/Huawei/VRP/display_version", value:buf);

    # Get firmware version.
    pattern = "VRP(?: \(R\))? [sS]oftware,\s*Version (\d(?:\.\d+)*)";
    match = eregmatch(string:buf, pattern:pattern);

    os_name = "Huawei Versatile Routing Platform";
    if (!isnull(match)) osname += " " + match[1];

    # Reset SSH connection.
    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
    buf = ssh_cmd(cmd:"display patch-information", nosh:TRUE, noexec:TRUE);
    if(buf && "Unrecognized command found at '^' position." >!< buf)
      set_kb_item(name:"Host/Huawei/VRP/display_patch-information",value:buf);

    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"embedded");

    _local_checks_enabled();
    report += '\n' + 'Local security checks have been enabled for Huawei Versatile Routing Platform.\n';
    security_note(port:0, extra:report);
    exit(0);
  }
}

#
# Make sure sudo is working
#
if ( NASL_LEVEL >= 3200 )
{
 if ( !CISCO && get_kb_item("Secret/SSH/sudo") )
 {
  buf = info_send_cmd(cmd: 'id');

  if ( ! buf )
  {
    report += '\n' + 'Note, though, that an attempt to elevate privileges using \'';
    sudo_path = get_kb_item("Secret/SSH/sudo_path");
    if (sudo_path) report += sudo_path;
    report += get_kb_item("Secret/SSH/sudo_method") + '\' failed\n';
    errmsg = ssh_cmd_error();
    if (errmsg) report +='for the following reason :\n\n' + errmsg + '\n\n';
    else report += 'for an unknown reason. ';
    report += 'Further commands will be run as the user';
    if (errmsg) report += ' ';
    else report += '\n';
    report += 'specified in the scan policy.\n';

    rm_kb_item(name:"Secret/SSH/sudo");
    rm_kb_item(name:"Secret/SSH/sudo-password");
  }
 }
}

# nb: IOS-XR needs to be handled before IOS / IOS-XE / ASA.
if (info_t == INFO_SSH && CISCO_IOS_XR)
{
  cmd = 'show version brief';
  buf = ssh_cmd(cmd:cmd, nosh:TRUE, cisco:FALSE);

  if (buf && "Cisco IOS XR Software," >< buf)
  {
    iosxr = egrep(pattern:"^.*IOS XR.*Version [0-9.]+.*", string:buf);
    if (iosxr)
    {
      set_kb_item(name:"Host/Cisco/IOS-XR", value:iosxr);
      _local_checks_enabled();
      set_kb_item(name:"Host/Cisco/show_ver", value:buf);

      # nb: 'ssh_cmd()' does not work on Cisco IOS XR without reopening the connection.
      #      And a call to 'sleep()' is needed between 'ssh_close_connection()' and
      #      'ssh_open_connection()'.
      ssh_close_connection();
      sleep(1);
      sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

      cmd = 'show running';
      buf2 = ssh_cmd(cmd:cmd, nosh:TRUE, cisco:FALSE);
      if (!isnull(buf2) && !egrep(pattern:"(^Building configuration|IOS XR Configuration)", string:buf2))
      {
        if ('^\r\n% ' >< buf2 || '^\r\nERROR: % ' >< buf2)
        {
          if ("% This command is not authorized" >< buf2)
          {
            report += '\n' + "Note that the user '" + get_kb_item("Secret/SSH/login") + "' is not in a task group that allows running" +
                      '\n' + "the '" + cmd + "' command." + '\n';
          }

          i = stridx(buf2, '^\r\n% ');
          if (i == -1) i = stridx(buf2, '^\r\nERROR: % ');

          # nb: make sure the error marker appears either at the start or
          #     after a series of spaces.
          if (i == 0 || (i > 0 && ereg(pattern:"^ +$", string:substr(buf2, 0, i-1))))
          {
            cmd_prompt = get_kb_item("/tmp/ssh_cmd/cmd_prompt");
            if (isnull(cmd_prompt)) cmd_prompt = "";
            set_kb_item(name:"Host/Cisco/show_running/errmsg", value:cmd_prompt+cmd+'\r\n'+buf2);
          }
        }
        buf2 = NULL;
      }
      if (buf2) set_kb_item(name:"Secret/Host/Cisco/show_running", value:buf2);

      report += '\n' + 'Local security checks have been enabled for Cisco IOS-XR.' +
                '\n';
      security_note(port:0, extra:report);
      exit(0);
    }
    else exit(1, "Failed to parse the Cisco IOS-XR version from the output of '"+cmd+"'.");
  }
  else if (!buf)
  {
    msg = "Execution of the command '"+cmd+"' failed.";
    error_msg = get_ssh_error();
    if (error_msg) msg += '\n' + error_msg;
    set_kb_item(name:'HostLevelChecks/failure', value:msg);
    exit(1, msg);
  }
  else exit(1, "Unknown Cisco IOS-XR behavior.");
}

if ( info_t == INFO_SSH && CISCO )
{
 report = '';

 cmd = 'show ver';
 buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:TRUE);

 if (!buf)
 {
   if (get_kb_item("Secret/SSH/enable-password"))
   {
     report += '\n' + 'Note, though, that an attempt to elevate privileges using \'enable\' failed\n';
     errmsg = ssh_cmd_error();
     if (errmsg) report +='for the following reason :\n\n' + errmsg + '\n\n';
     else report += 'for an unknown reason. ';
     report += 'Further commands will be run as the user';
     if (errmsg) report += ' ';
     else report += '\n';
     report += 'specified in the scan policy.\n';

     rm_kb_item(name:"Secret/SSH/enable-password");
     set_kb_item(name:"Host/Cisco/enable-password-failure", value:TRUE);

     # NB: 'ssh_cmd()' does not work on Cisco without reopening the connection.
     ssh_close_connection();
     sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
     if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

     buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:TRUE);
   }
  }

 if (!buf)
 {
   msg = "Execution of the command '"+cmd+"' failed.";
   error_msg = get_ssh_error();
   if (error_msg) msg += '\n' + error_msg;
   set_kb_item(name:'HostLevelChecks/failure', value:msg);
   exit(1, msg);
 }

 idx = stridx(buf, "Cisco IOS Software,");
 if ( idx > 0 )
 {
   # in some IOS XE installs, the second line of "show ver" contains "Cisco IOS Software,"
   #  and by removing the preceding lines, it erases the IOS XE version line
   if (("Cisco IOS XE Software" >!< buf) && ("Cisco IOS-XE Software" >!< buf))
     buf = substr(buf, idx, strlen(buf) - 1);
 }
 # check for FWSM
 else if (
   "FWSM Firewall Version" >< buf
 )
 {
  fwsmpat = "FWSM Firewall Version (\d+\.\d+\(\d+\))";
  match = eregmatch(pattern:fwsmpat, string:buf);
  if(!isnull(match)) set_kb_item(name:"Host/Cisco/FWSM/Version", value:match[1]);

  # FWSM runs on catalyst switches which run IOS; however, it is not
  # possible to get the IOS version being run from within FWSM.
  report += '\n' + 'Although local, credentialed checks for Cisco Catalyst switches' +
            '\n' + 'running the FWSM Firewall module are not available, Nessus has managed' +
            '\n' + 'to run commands in support of OS fingerprinting.' +
            '\n';

  set_kb_item(name:"Host/OS/showver", value:"Cisco FWSM Firewall");
  set_kb_item(name:"Host/OS/showver/Confidence", value:100);
  set_kb_item(name:"Host/OS/showver/Type", value:"firewall");
  get_cisco_mac_addrs("FWSM");

  security_note(port:0, extra:report);
  exit(0);
 }
 # check for Cisco ACE.
 else if (
   "Cisco Application Control Software (ACSW)" >< buf &&
   "system:" >< buf
 )
 {
   match = eregmatch(pattern:"system:[ \t]+Version[ \t]+(A[0-9].+)[ \t]+\[build ", string:buf);
   if (!isnull(match)) set_kb_item(name:"Host/Cisco/ACE/Version", value:match[1]);
   get_cisco_mac_addrs("ACE");
   _local_checks_enabled();
   # nb: Cisco ACE runs on IOS, but we don't currently have a way to get
   #     the version of the IOS itself.
   report = '\n' + 'Local security checks have been enabled for Cisco Application Control' +
            '\n' + 'Engine (ACE).' +
            '\n';
   security_note(port:0, extra:report);
   exit(0);
 }
 else
 {
   idx = stridx(buf, "Cisco Adaptive Security Appliance Software ");
   if ( idx > 0 ) buf = substr(buf, idx, strlen(buf) - 1);
 }

 # NB: 'ssh_cmd()' does not work on Cisco without reopening the connection.
 ssh_close_connection();
 sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
 if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

 cmd = 'show running';
 buf2 = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:TRUE);
 if (!isnull(buf2) && !egrep(pattern:"^(version|enable|end)", string:buf2))
 {
   if ('^\r\n% ' >< buf2 || '^\r\nERROR: % ' >< buf2)
   {
     i = stridx(buf2, '^\r\n% ');
     if (i == -1) i = stridx(buf2, '^\r\nERROR: % ');

     # nb: make sure the error marker appears either at the start or
     #     after a series of spaces.
     if (i == 0 || (i > 0 && ereg(pattern:"^ +$", string:substr(buf2, 0, i-1))))
     {
       cmd_prompt = get_kb_item("/tmp/ssh_cmd/cmd_prompt");
       if (isnull(cmd_prompt)) cmd_prompt = "";
       set_kb_item(name:"Host/Cisco/show_running/errmsg", value:cmd_prompt+cmd+'\r\n'+buf2);
     }
   }
   buf2 = NULL;
 }

 # NB: 'ssh_cmd()' does not work on Cisco without reopening the connection.
 ssh_close_connection();
 sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
 if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

 cmd = 'show software version';
 buf3 = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:TRUE);

 if (!isnull(buf3) && !egrep(pattern:"^(Copyright|Technical Support)", string:buf3))
 {
   if ('^\r\n% ' >< buf3 || '^\r\nERROR: % ' >< buf3)
   {
     i = stridx(buf3, '^\r\n% ');
     if (i == -1) i = stridx(buf3, '^\r\nERROR: % ');

     # nb: make sure the error marker appears either at the start or
     #     after a series of spaces.
     if (i == 0 || (i > 0 && ereg(pattern:"^ +$", string:substr(buf3, 0, i-1))))
     {
       cmd_prompt = get_kb_item("/tmp/ssh_cmd/cmd_prompt");
       if (isnull(cmd_prompt)) cmd_prompt = "";
       set_kb_item(name:"Host/Cisco/show_software_version/errmsg", value:cmd_prompt+cmd+'\r\n'+buf3);
     }
   }

   buf3 = NULL;
 }

 # Run some commands if there's an audit in the scan policy.
 if (strlen(get_preference("Cisco IOS Compliance Checks[file]:Policy file #1 :")) > 0)
 {
   commands = make_list(
     'show config',
     'show running all',
     'show startup',
     'show snmp user'
   );

   foreach cmd (commands)
   {
     ssh_close_connection();
     sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
     if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

     cmd_no_spaces = str_replace(find:" ", replace:"_", string:cmd);

     cmd_output = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:TRUE);
     if (isnull(cmd_output))
     {
       set_kb_item(name:"Host/Cisco/"+cmd_no_spaces+"/errmsg", value:"The command failed to produce any output.");
     }
     else
     {
       if ('^\r\n% ' >< cmd_output || '^\r\nERROR: % ' >< cmd_output)
       {
         i = stridx(cmd_output, '^\r\n% ');
         if (i == -1) i = stridx(cmd_output, '^\r\nERROR: % ');

         # nb: make sure the error marker appears either at the start or
         #     after a series of spaces.
         if (i == 0 || (i > 0 && ereg(pattern:"^ +$", string:substr(cmd_output, 0, i-1))))
         {
           cmd_prompt = get_kb_item("/tmp/ssh_cmd/cmd_prompt");
           if (isnull(cmd_prompt)) cmd_prompt = "";
           set_kb_item(name:"Host/Cisco/"+cmd_no_spaces+"/errmsg", value:cmd_prompt+cmd+'\r\n'+cmd_output);
         }
         else set_kb_item(name:"Host/Cisco/"+cmd_no_spaces+"/errmsg", value:"An unknown error occurred :"+'\r\n'+cmd_output);
       }
       else set_kb_item(name:"Host/Cisco/"+cmd_no_spaces, value:cmd_output);
     }
   }
 }

 if (iosxe = egrep(pattern:"^.* IOS[ -]XE Software.*, Version [0-9][0-9.A-Za-z\(\)]+,?", string:buf))
 {
  set_kb_item(name:"Host/Cisco/IOS-XE", value:iosxe);
  _local_checks_enabled();
  set_kb_item(name:"Host/Cisco/show_ver", value:buf);
  if (buf2) set_kb_item(name:"Secret/Host/Cisco/show_running", value:buf2);
  if (buf3) set_kb_item(name:"Host/Cisco/show_software_version", value:buf3);
  get_cisco_mac_addrs("IOS-XE");
  report = '\n' + 'Local security checks have been enabled for Cisco IOS-XE.' +
           '\n' + report;
  security_note(port:0, extra:report);
  exit(0);
 }
 else if (denali = egrep(pattern:"^.*IOS.*Version (Denali|Everest) [0-9.]+.*", string:buf))
 {
  set_kb_item(name:"Host/Cisco/IOS-XE", value:denali);
  _local_checks_enabled();
  set_kb_item(name:"Host/Cisco/show_ver", value:buf);
  if (buf2) set_kb_item(name:"Secret/Host/Cisco/show_running", value:buf2);
  if (buf3) set_kb_item(name:"Host/Cisco/show_software_version", value:buf3);
  get_cisco_mac_addrs("IOS-XE");
  report = '\n' + 'Local security checks have been enabled for Cisco IOS-XE.' +
           '\n' + report;
  security_note(port:0, extra:report);
  exit(0);
 }
 else if (  ios = ereg(pattern:"^.*IOS.*Version [0-9.]+\(.*\).*", string:buf, multiline:TRUE) )
 {
  set_kb_item(name:"Host/Cisco/IOS", value:ios);
  _local_checks_enabled();
  set_kb_item(name:"Host/Cisco/show_ver", value:buf);
  if (buf2) set_kb_item(name:"Secret/Host/Cisco/show_running", value:buf2);
  if (buf3) set_kb_item(name:"Host/Cisco/show_software_version", value:buf3);
  get_cisco_mac_addrs("Cisco IOS");
  report = '\n' + 'Local security checks have been enabled for Cisco IOS.' +
           '\n' + report;
  security_note(port:0, extra:report);
  exit(0);
 }
 else if ( asa_cx = egrep(pattern:"^Cisco ASA CX Platform[0-9\. ]+.*", string:buf) ) {
  # extract version
  asa_cx_ver = eregmatch(string:asa_cx, pattern:"Platform\s+([0-9\.]+)\s*(\([0-9\.]+\))?");
  if (asa_cx_ver)
  {
    asa_cx_ver = asa_cx_ver[1] + asa_cx_ver[2];
    set_kb_item(name:"Host/Cisco/ASA-CX/Version", value:asa_cx_ver);
  }

  # OS fingerprinting
  set_kb_item(name:"Host/OS/showver", value:asa_cx);
  set_kb_item(name:"Host/OS/showver/Confidence", value:100);
  set_kb_item(name:"Host/OS/showver/Type", value:"embedded");

  # local check information
  set_kb_item(name:"Host/Cisco/ASA-CX", value:asa_cx);
  _local_checks_enabled();
  set_kb_item(name:"Host/Cisco/show_ver", value:buf);
  if (buf2) set_kb_item(name:"Secret/Host/Cisco/show_running", value:buf2);

  report = '\n' + 'Local security checks have been enabled for Cisco ASA CX.' +
           '\n' + report;
  security_note(port:0, extra:report);
  exit(0);
 }
 else if ( asa = egrep(pattern:"^Cisco Adaptive Security Appliance Software Version [0-9.]+\(.*\).*", string:buf) )
 {
  model = eregmatch(string:buf, pattern:'\\nHardware: *ASA *([^,]+?)?(,|\\r\\n|$)');
  if (!isnull(model))
    set_kb_item(name:"Host/Cisco/ASA/model", value:model[1]);

  # determine if the system is SMP or not
  image = eregmatch(string:buf, pattern:'\\nSystem image file is "[^:]+:/([^"]+)');
  if (!isnull(image))
  {
    set_kb_item(name:"Host/Cisco/ASA/image", value:image[1]);
    if ( "-smp-" >< image[1] )
      set_kb_item(name:"Host/Cisco/ASA/SMP", value:TRUE);
  }

  # OS fingerprinting
  set_kb_item(name:"Host/OS/showver", value:asa);
  set_kb_item(name:"Host/OS/showver/Confidence", value:100);
  set_kb_item(name:"Host/OS/showver/Type", value:"embedded");
  get_cisco_mac_addrs("ASA");
  # local check information
  set_kb_item(name:"Host/Cisco/ASA", value:asa);
  _local_checks_enabled();
  set_kb_item(name:"Host/Cisco/show_ver", value:buf);
  if (buf2) set_kb_item(name:"Secret/Host/Cisco/show_running", value:buf2);
  if (buf3) set_kb_item(name:"Host/Cisco/show_software_version", value:buf3);

  report = '\n' + 'Local security checks have been enabled for Cisco ASA.' +
           '\n' + report;
  security_note(port:0, extra:report);
  exit(0);
 }
 exit(1, "Unknown remote Cisco behavior.");
}

# ASR55xx uses StarOS, not IOS-XE
# This arrives after KEX
user_banner = get_ssh_banner();
if (!isnull(user_banner) && user_banner != "" && "Cisco Systems ASR5" ><  user_banner && !CISCO)
{
  model = pregmatch(string:user_banner, pattern:"Cisco Systems ASR(\d+) Intelligent Mobile Gateway");
  if (!isnull(model))
    set_kb_item(name:"Host/Cisco/ASR/Model", value:model[1]);

  # This was the only output available for development
  buf = ssh_cmd(cmd:'show version verbose', nosh:TRUE, nosudo:TRUE, noexec:TRUE);
  if (!isnull(buf))
    set_kb_item(name:"Host/Cisco/ASR/show_version_verbose", value:buf);
  if(preg(pattern:"Kernel Version.*-staros-.*", string:buf, multiline:TRUE))
  {
    set_kb_item(name:"Host/Cisco/StarOS", value:TRUE);
    ver = pregmatch(pattern:"Image Version: +([\d\.\(\)A-Za-z]+)", string:buf);
    if (!isnull(ver))
      set_kb_item(name:"Host/Cisco/StarOS/Version", value:ver[1]);

    build = pregmatch(pattern:"Image Build Number: +(\d+)", string:buf);
    if (!isnull(build))
      set_kb_item(name:"Host/Cisco/StarOS/Build", value:build[1]);

    _local_checks_enabled();
    report = '\nLocal security checks have been enabled for Cisco StarOS.' +
             '\n';
    security_note(port:0, extra:report);
    exit(0);
  }
}

buf = info_send_cmd(cmd:'uname -a');
uname_a = buf;
if("linux" >< tolower(buf))
  set_kb_item(name:"Host/Linux", value:TRUE);

# Brocade Switch with Fabric OS
# or IBM Storwize
if (
  !buf &&
  'rbash: sh: command not found' >< ssh_cmd_error()
)
{
  cmd = "version";
  buf = ssh_cmd(cmd:cmd, nosh:TRUE);
  if (buf)
  {
    # Brocade Switch with Fabric OS
    set_kb_item(name:"Host/Brocade/Fabos/"+cmd, value:buf);

    os = NULL;
    kernel = NULL;

    foreach line (split(buf, keep:FALSE))
    {
      match = eregmatch(pattern:"^Fabric OS: +v([0-9]+\.[^ ]+)$", string:line);
      if (!isnull(match))
      {
        os = match[1];
        continue;
      }

      match = eregmatch(pattern:"^Kernel: +([0-9]+\.[0-9]+)", string:line);
      if (!isnull(match))
      {
        kernel = match[1];
        continue;
      }

      if (os)
      {
        if (kernel) os = 'Linux Kernel ' + kernel + ' on Brocade Switch with Fabric OS ' + os;
        set_kb_item(name:"Host/OS/showver", value:os);
        set_kb_item(name:"Host/OS/showver/Confidence", value:100);
        set_kb_item(name:"Host/OS/showver/Type", value:"switch");
        break;
      }
    }

    cmd = "configshow";
    buf = ssh_cmd(cmd:cmd, nosh:TRUE);
    if (buf) set_kb_item(name:"Host/Brocade/Fabos/"+cmd, value:buf);

    cmd = "ipfilter --show";
    buf = ssh_cmd(cmd:cmd, nosh:TRUE);
    if (buf) set_kb_item(name:"Host/fwrules/output/"+cmd, value:buf);

    cmd = "uptime";
    buf = ssh_cmd(cmd:cmd, nosh:TRUE);
    if (buf) set_kb_item(name:"Host/last_reboot", value:buf);

    exit(0, "Local security checks for Brocade's Fabric OS are NOT supported.");
  }
  else
  {
    # IBM Storwize?
    cmd = "sainfo lsservicestatus";
    buf = ssh_cmd(cmd:cmd, nosh:TRUE);
    if (buf) {
      set_kb_item(name:"Host/IBM/Storwize/"+cmd, value:buf);

      version = NULL;
      build = NULL;
      machine_type = "unknown";
      machine_major = NULL;

      foreach line (split(buf, keep:FALSE))
      {
        match = eregmatch(pattern:"^node_code_version (.*)$", string:line);
        if (!isnull(match))
        {
          version = match[1];
          continue;
        }

        match = eregmatch(pattern:"^node_code_build (.*)$", string:line);
        if (!isnull(match))
        {
          build = match[1];
          continue;
        }

        match = eregmatch(pattern:"^product_mtm (.*)-.*$", string:line);
        if (!isnull(match))
        {
          machine_type = match[0] - "product_mtm ";
          machine_major = match[1];
          continue;
        }
      }

      set_kb_item(name:"Host/IBM/Storwize/machine_major", value:machine_major);
      set_kb_item(name:"Host/IBM/Storwize/machine_type", value:machine_type);
      if (version) set_kb_item(name:"Host/IBM/Storwize/version", value:version);
      if (build) set_kb_item(name:"Host/IBM/Storwize/build", value:build);

      exit(0, "Local security checks for IBM Storwize are NOT supported.");
    }
    else exit(1, "Unknown device running rbash.");
  }
}

# VMware NSX
if (!buf && "vtysh: invalid option -- 'c'" >< ssh_cmd_error())
{
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  buf2 = ssh_cmd(cmd:'show version', nosudo:TRUE, nosh:TRUE, noexec:TRUE);

  os      = NULL;
  version = NULL;
  build   = NULL;
  kernel  = NULL;
  if ('System type:' >< buf2 && 'NSX Manager' >< buf2)
  {
    os = "VMware NSX";
    nsx_product = "Manager";

    if ("System Version:" >< buf2)
    {
      chunk = strstr(buf2, 'System Version:') - 'System Version:';
      chunk = str_replace(string:chunk, find:' ', replace:'');
      chunk = chomp(chunk);
      items = split(chunk, sep:'-', keep:FALSE);
      if (max_index(items) == 2)
      {
        version = items[0];
        build   = items[1];
      }
      else
      {
        if (chunk =~ '^[0-9\\.]+$') version = chunk;
      }
    }
  }
  else if ('Name:' >< buf2 && 'vShield Edge' >< buf2)
  {
    os = "VMware NSX";
    nsx_product = "Edge";

    lines = split(buf2,sep:'\n',keep:FALSE);
    foreach line (lines)
    {
      if ( "Version:" >< line )
      {
        value = eregmatch(string:line, pattern:'^Version:[\\s\\t]*([0-9]+(?:\\.[0-9]+)*)$');
        if (value[1]) version = value[1];
      }
      else if ( "Build number:" >< line )
      {
        value = eregmatch(string:line, pattern:'^Build number:[\\s\\t]*([0-9]+)$');
        if (value[1]) build = value[1];
      }
      else if ( "Kernel:" >< line )
      {
        value = eregmatch(string:line, pattern:'^Kernel:[\\s\\t]*([0-9]+(?:\\.[0-9]+)*)$');
        if (value[1]) kernel = value[1];
      }
    }

    buf3 = ssh_cmd(cmd:'show service sslvpn-plus', nosudo:TRUE, nosh:TRUE, noexec:TRUE, cisco:TRUE);
    sslvpn = "unknown";
    if (buf3)
    {
      set_kb_item(name:"Host/VMware NSX/show_service_sslvpn-plus", value:buf3);
      if ( "is not running" >< buf3 ) sslvpn = FALSE;
      else if ( "is running"  >< buf3 ) sslvpn = TRUE;
    }
    set_kb_item(name:"Host/VMware NSX/SSLVPN-Plus", value:sslvpn);
  }
  if (os)
  {
    set_kb_item(name:"Host/VMware NSX/show_version", value:buf2);
    set_kb_item(name:"Host/VMware NSX/Product", value:nsx_product);

    set_kb_item(name:"Host/OS/showver", value:os);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"embedded");

    os = os + " " + nsx_product;
    if (version)
    {
      os = os + " " + version;
      set_kb_item(name:"Host/VMware NSX/Version", value:version);
      if (build)
      {
        os = os + " Build " + build;
        set_kb_item(name:"Host/VMware NSX/Build", value:build);
      }
      if (kernel) set_kb_item(name:"Host/VMware NSX/Kernel", value:kernel);
      _local_checks_enabled();

      report += '\n' + 'The remote VMware NSX system is : ' + (os - "VMware NSX ") +
                '\n' +
                '\n' + 'Local security checks have been enabled for this host.\n';
    }
    else
    {
      report += '\n' + 'Local security checks have NOT been enabled for this ' + os +
                '\n' + 'host because Nessus was not able to identify its version.\n';
    }
  }

  security_note(port:0, extra:report);
  exit(0);
}
if (
  (
    buf &&
    (
      "Cmd exec error" >< buf ||
      "Cmd parse error" >< buf ||
      'Syntax error while parsing' >< buf ||
      'Error: Received invalid command line argument' >< buf
    )
  ) ||
  (
    !buf &&
    "Error getting tty, exiting" >< ssh_cmd_error()
  )
)
{
  # NB: 'ssh_cmd()' does not work on Cisco without reopening the connection.
  ssh_close_connection();
  sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
  if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

  buf2 = ssh_cmd(cmd:'show ver', nosudo:TRUE, nosh:TRUE, cisco:TRUE, noclose:TRUE);
  ssh_cmd(cmd:'exit', nosudo:TRUE, nosh:TRUE, cisco:TRUE, nosetup:TRUE);
  ssh_close_connection();

  if (buf2 && "Cisco Nexus Operating System (NX-OS) Software" >< buf2)
  {
   buf = buf2;

   if (ver = eregmatch(string:buf, pattern:"system:\s+version\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*"))
     os_name = "Cisco NX-OS Version " + ver[1];
   else
     os_name = "Cisco NX-OS";
   get_cisco_mac_addrs("NX-OS");
   # OS fingerprint info.
   set_kb_item(name:"Host/OS/showver", value:os_name);
   set_kb_item(name:"Host/OS/showver/Confidence", value:100);
   set_kb_item(name:"Host/OS/showver/Type", value:"switch");

   # Run some commands if there's an audit in the scan policy.
   if (strlen(get_preference("Cisco IOS Compliance Checks[file]:Policy file #1 :")) > 0)
   {
     commands = make_list(
       'show startup-config',
       'show running-config'
     );

     foreach cmd (commands)
     {
       ssh_close_connection();
       sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
       if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

       cmd_no_spaces = str_replace(find:" ", replace:"_", string:cmd);

       cmd_output = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:TRUE);
       if (isnull(cmd_output))
       {
         set_kb_item(name:"Host/Cisco/"+cmd_no_spaces+"/errmsg", value:"The command failed to produce any output.");
       }
       else
       {
         set_kb_item(name:"Host/Cisco/"+cmd_no_spaces, value:cmd_output);
       }
     }
   }

   # local check info
   set_kb_item(name:"Host/Cisco/show_ver", value:buf);
   set_kb_item(name:"Host/Cisco/NX-OS", value:TRUE);
   _local_checks_enabled();
   report += '\n' + 'Local security checks have been enabled for Cisco NX-OS.\n';
   security_note(port:0, extra:report);
   exit(0);
  }
  else if (buf2 && "Cisco Application Control Software (ACSW)" >< buf2)
  {
    buf = buf2;
    set_kb_item(name:"Host/Cisco/show_ver", value:buf);

    os_name = "Cisco Application Control Engine (ACE)";
    set_kb_item(name:"Host/Cisco/ACE", value:TRUE);

    ver = NULL;
    match = eregmatch(pattern:"system:[ \t]+Version[ \t]+(A[0-9].+)[ \t]+\[build ", string:buf);
    if (!isnull(match))
    {
      ver = match[1];
      set_kb_item(name:"Host/Cisco/ACE/Version", value:ver);

      os_name += " version " + ver;
    }

    report += '\n' + 'The remote operating system is : ' + os_name +
              '\n';

    # OS fingerprint info.
    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"load-balancer");

    if (ver)
    {
      report += '\n' + 'Local security checks have been enabled for this host.' +
                '\n';
      _local_checks_enabled();
    }
    else
    {
      report += '\n' + 'Local security checks have NOT been enabled for this host' +
                '\n' + 'because the plugin failed to extract the system version' +
                '\n' + "information from the output of 'show ver'." +
                '\n';
      set_kb_item(name:'HostLevelChecks/failure', value:"Failed to extract system version");
    }
    security_note(port:0, extra:report);
    exit(0);
  }
  else if (buf2 && "Cisco Application Deployment Engine OS" >< buf2)
  {
    buf = buf2;
    set_kb_item(name:"Host/Cisco/show_ver", value:buf);

    # NB: 'ssh_cmd()' does not work on Cisco without reopening the connection.
    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
    
    # Some devices (e.g. ISE) allow session resuming and only 5 sessions by default
    # so we explicitly exit out instead of leaving disconnected sessions
    buf2 = ssh_cmd(cmd:'show running-config', nosudo:TRUE, nosh:TRUE, cisco:TRUE, noclose:TRUE);
    ssh_cmd(cmd:'exit', nosudo:TRUE, nosh:TRUE, cisco:TRUE, nosetup:TRUE);
    ssh_close_connection();

    if (!egrep(pattern:"^(logging loglevel|password-policy)", string:buf2)) buf2 = NULL;

    prod = ver = NULL;
    buf = strstr(buf, "Version information of installed applications");

    foreach line (split(buf, keep:FALSE))
    {
      if (ereg(pattern:"^Cisco", string:line))
      {
        prod = chomp(line);
        prod = ereg_replace(string:prod, pattern:"^(.*[^-])(-*)$", replace:"\1");
        prod = chomp(prod);
        if (" VERSION INFORMATION" >< prod) prod = prod - " VERSION INFORMATION";

      }
      else
      {
        match = eregmatch(pattern:"^[ \t]*Version[ \t]*:[ \t]*(.+)$", string:line);
        if (!isnull(match)) ver = match[1];
      }
      if (!isnull(prod) && !isnull(ver)) break;
    }

    if (!isnull(prod))
    {
      os_name = prod;
      if (!isnull(ver)) os_name += " " + ver;

      # os fingerprint info
      set_kb_item(name:"Host/OS/showver", value:os_name);
      set_kb_item(name:"Host/OS/showver/Confidence", value:100);
      set_kb_item(name:"Host/OS/showver/Type", value:"embedded");

      # local check info
      kb_base = "Host/Cisco/";
      if ("ACS" >< prod) kb_name = kb_base + "ACS";
      else if ("Identity Services Engine" >< prod)
      {
        kb_name = kb_base + "ISE";
        if (!isnull(ver)) set_kb_item(name:kb_name + "/version", value:ver);
      }
      else if ("Prime LAN Management Solution" >< prod) kb_name = kb_base + "Prime_LMS";
      else if ("Prime Network Control System" >< prod) kb_name = kb_base + "Prime_NCS";
      else kb_name = kb_base + ereg_replace(pattern:" +", replace:"_", string:prod);

      set_kb_item(name:kb_name, value:TRUE);
      if (buf2) set_kb_item(name:"Secret/"+kb_name+"/show_running", value:buf2);

      if (
        kb_name =~ 'Prime_NCS$' ||
        kb_name =~ 'ACS$' ||
        kb_name =~ 'ISE$'
      )
      {
        report += '\n' + 'Local security checks have been enabled for '+prod+'.\n';
        _local_checks_enabled();
      }
      else
        report += '\n' + 'Local security checks have NOT been enabled for '+prod+'.\n';
      security_note(port:0, extra:report);
      exit(0);
    }
    else buf = "";
  }
  else if (buf2 && "NAM application image" >< buf2)
  {
    buf = buf2;
    set_kb_item(name:"Host/Cisco/show_ver", value:buf);

    ver = eregmatch(string:buf, pattern:"NAM application image version: ([0-9].+)");
    if (isnull(ver)) os_name = "Cisco Network Analysis Module (NAM)";
    else os_name = "Cisco Network Analysis Module (NAM) Version " + ver[1];

    # os fingerprint info
    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"embedded");

    # Collect model info.
    buf = ssh_cmd(cmd:"show model", nosh:TRUE);
    if (buf) set_kb_item(name:"Host/show_model", value:buf);

    # local check info
    set_kb_item(name:"Host/Cisco/NAM", value:TRUE);
    report += '\n' + 'Local security checks have NOT been enabled for Cisco NAM.\n';
    security_note(port:0, extra:report);
    exit(0);
  }
  else if (buf2 && "Cisco Intrusion Prevention System" >< buf2)
  {
    buf = buf2;
    set_kb_item(name:"Host/Cisco/show_ver", value:buf);

    ver = eregmatch(string:buf, pattern:"Cisco Intrusion Prevention System, Version ([0-9].+)");
    if (isnull(ver)) os_name = "Cisco Intrusion Prevention System";
    else os_name = "Cisco Intrusion Prevention System Version " + ver[1];

    # OS fingerprint info
    set_kb_item(name:"Host/OS/showver", value:os_name);
    set_kb_item(name:"Host/OS/showver/Confidence", value:100);
    set_kb_item(name:"Host/OS/showver/Type", value:"embedded");

    # local check info
    set_kb_item(name:"Host/Cisco/IPS", value:TRUE);
    report += '\n' + 'Local security checks have been enabled for Cisco Intrusion' +
             '\n' + 'Prevention System.\n';
    _local_checks_enabled();
    security_note(port:0, extra:report);
    exit(0);
  }
  else buf = "";
}

if (
  (
    buf &&
    "Syntax error while parsing " >!< buf
  ) ||
  (
    !buf &&
    'error: syntax error, expecting <command>: -c' >< ssh_cmd_error()
  )
)
{
  # Arista EOS
  if ('\n% Invalid input at line 1\n' >< buf)
  {
    buf = ssh_cmd(cmd:'show version', nosh:TRUE);
    if (buf && "Arista " >< buf)
    {
      set_kb_item(name:"Host/Arista/show_version", value:buf);

      os = 'Arista EOS';

      arch = NULL;
      model = NULL;
      version = NULL;
      uptime = NULL;

      foreach line (split(buf, keep:FALSE))
      {
        match = eregmatch(pattern:"^Arista[ \t]+([^ ]+)", string:line);
        if (!isnull(match))
        {
          model = match[1];
          continue;
        }

        match = eregmatch(pattern:"^Software image version:[ \t]+([0-9]+\.[^ ]+)", string:line);
        if (!isnull(match))
        {
          version = match[1];
          continue;
        }

        match = eregmatch(pattern:"^Architecture:[ \t]+(.+)", string:line);
        if (!isnull(match))
        {
          arch = match[1];
          continue;
        }

        match = eregmatch(pattern:"^Uptime:[ \t]+(.+)", string:line);
        if (!isnull(match))
        {
          uptime = match[1];
          continue;
        }
      }

      if (version)
      {
        os += ' ' + version;
        if (arch) os += ' (' + arch + ')';
        if (model) os += ' on a ' + model;
      }

      set_kb_item(name:"Host/OS/showver", value:os);
      set_kb_item(name:"Host/OS/showver/Confidence", value:100);
      set_kb_item(name:"Host/OS/showver/Type", value:"switch");

      if (uptime) set_kb_item(name:"Host/last_reboot", value:uptime);

      report += '\n' + 'Although local, credentialed checks for Arista EOS are not available,' +
                '\n' + 'Nessus has managed to run commands in support of OS fingerprinting.' +
                '\n';
      security_note(port:0, extra:report);
      exit(0);
    }
    else exit(1, "Unknown Arista EOS behavior.");
  }
  # Check Point Gaia
  else if ('CLINFR0329  Invalid command:' >< buf)
  {
    # eg:
    #   Product version Check Point Gaia R75.40
    #   OS build 65
    #   OS kernel version 2.6.18-92cp
    #   OS edition 32-bit
    buf = ssh_cmd(cmd:'show version all', nosh:TRUE);
    if (buf)
    {
      set_kb_item(name:"Host/Check_Point/show_ver", value:buf);

      os = NULL;
      kernel = NULL;

      foreach line (split(buf, keep:FALSE))
      {
        match = eregmatch(pattern:"^Product version (Check Point .+ R[0-9.]+) *$", string:line);
        if (!isnull(match))
        {
          os = match[1];
          continue;
        }

        # nb: we're not interested in granular kernel version info.
        match = eregmatch(pattern:"^OS kernel version ([0-9]+\.[0-9]+)", string:line);
        if (!isnull(match))
        {
          kernel = match[1];
          continue;
        }

        if (os)
        {
          if (kernel) os = 'Linux Kernel ' + kernel + ' on ' + os;
          set_kb_item(name:"Host/OS/showver", value:os);
          set_kb_item(name:"Host/OS/showver/Confidence", value:100);
          set_kb_item(name:"Host/OS/showver/Type", value:"firewall");
          break;
        }
      }

      # foreach component (make_list('fw', 'vpn'))
      # {
      #   cmd = component + ' ver';
      #   buf = ssh_cmd(cmd:cmd, nosh:TRUE);
      #   if (buf)
      #   {
      #     matches = egrep(pattern:"^This is (Check Point .+)$", string:buf);
      #     if (matches) set_kb_item(name:"Host/Check_Point/"+component+"_ver", matches);
      #   }
      # }

      buf = ssh_cmd(cmd:"show uptime", nosh:TRUE);
      if (buf)
      {
        last = "";
        foreach line (split(buf))
          if (!ereg(pattern:"^CLINFR[0-9]+", string:line)) last += line;
        if (last) set_kb_item(name:"Host/last_reboot", value:last);
      }

      exit(0, "Local security checks for Check Point Gaia are not supported.");
    }
    else exit(1, "Unknown Check Point behavior.");
  }
  # junos
  # if we get an error generated by the junos CLI, or we have a regular shell on a junos box
  else if (
    'error: syntax error, expecting <command>: -c' >< ssh_cmd_error() ||
    buf =~ '^JUNOS'
  )
  {
    shell = FALSE;

    if (buf =~ '^JUNOS')
    {
      set_kb_item(name:"Host/uname", value:buf);
      buf = info_send_cmd(cmd:'cli show version detail \\| no-more');
      last = info_send_cmd(cmd:'cli show chassis routing-engine \\| no-more');
      config = info_send_cmd(cmd:'cli show configuration \\| display set \\| no-more');
      shell = TRUE;
    }
    else
    {
      buf = ssh_cmd(cmd:'show version detail | no-more\r\n', nosudo:TRUE, nosh:TRUE);
      last = ssh_cmd(cmd:'show chassis routing-engine | no-more\r\n',nosudo:TRUE,nosh:TRUE);
      config = ssh_cmd(cmd:'show configuration | display set | no-more\r\n', nosudo:TRUE, nosh:TRUE);
      shell = FALSE;
    }

    if (buf)
    {
      # os fingerprinting hack for when we get the CLI (>) instead of a shell (%)
      if (!shell && (ver = eregmatch(pattern:"JUNOS Software Release \[([^\]]+)\]", string:buf)))
      {
        set_kb_item(name:"Host/OS/showver", value:"Juniper Junos Version " + ver[1]);
        set_kb_item(name:"Host/OS/showver/Confidence", value:100);
        set_kb_item(name:"Host/OS/showver/Type", value:"embedded");
      }

      # Get time of last reboot.
      if (last)
      {
        foreach line (split(last, keep:FALSE))
        {
          match = eregmatch(pattern:"Start time[ \t]+(.+)$", string:line);
          if (match)
          {
            set_kb_item(name:"Host/last_reboot", value:match[1]);
            break;
          }
        }
      }

      if (config)
      {
        kb = "Secret/Host/Juniper/JUNOS/config/show_configuration_|_display_set";
        set_kb_item(name:kb, value:config);
      }
      set_kb_item(name:"Host/Juniper/JUNOS/shell", value:shell);
      _local_checks_enabled();
      set_kb_item(name:"Host/Juniper/show_ver", value:buf);

      get_junos_mac_addrs(shell);

      report += '\nLocal security checks have been enabled for Juniper Junos.\n';
      security_note(port:0, extra:report);
      exit(0);
    }
  }
  # NetScaler
  else if (
    (
      'ERROR: Session expired or killed. Please login again' >< buf ||
      'Done\n' >< buf
    ) &&
    'ERROR: Ambiguous (use cmd completion for options)' >< buf
  )
  {
    # NB: 'ssh_cmd()' does not work on NetScaler without reopening the connection.
    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

    cmd = 'show ns version';
    buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE);
    if (!isnull(buf) && "NetScaler NS" >< buf)
    {
      set_kb_item(name:"Host/NetScaler/show_version", value:buf);

      os = NULL;
      build = NULL;

      # eg, "NetScaler NS10.0: Build 70.7.nc, Date: Sep  7 2012, 15:33:28  "
      foreach line (split(buf, keep:FALSE))
      {
        match = eregmatch(pattern:"^[ \t]*NetScaler NS([0-9.]+):[ \t]+Build ([0-9][^ \t,]+), Date", string:line);
        if (!isnull(match))
        {
          os = match[1];
          build = match[2];
          continue;
        }
        if (os)
        {
          os = 'Citrix NetScaler ' + os + " Build " + build;
          set_kb_item(name:"Host/OS/showver", value:os);
          set_kb_item(name:"Host/OS/showver/Confidence", value:100);
          set_kb_item(name:"Host/OS/showver/Type", value:"embedded");
          break;
        }
      }

      ssh_close_connection();
      sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

      cmd = 'show ns hardware';
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE);
      if (!isnull(buf) && "Platform:" >< buf)
      {
        set_kb_item(name:"Host/NetScaler/show_hardware", value:buf);
      }

      ssh_close_connection();
      sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

      cmd = 'show ns feature';
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE);
      if (!isnull(buf) && "Acronym" >< buf)
      {
        set_kb_item(name:"Host/NetScaler/show_feature", value:buf);
      }

      # nb: citrix_netscaler_detect.nbin sets 'Host/local_checks_enabled'.
      report += '\n' + 'Local security checks have been enabled for Citrix NetScaler.\n';
      security_note(port:0, extra:report);
      exit(0);
    }
    else exit(1, "Unknown Citrix NetScaler behavior.");
  }
  else if (
    # AsyncOS, used by different Cisco IronPort appliances
    'Unknown command: sh' >< buf || # Web Security Virtual Appliance 7.7.5-190
    'Unknown command or missing feature key: sh' >< buf # Email Security Virtual Appliance 8.0.0-671
  )
  {
    output = ssh_cmd(cmd:'version\r\n', nosudo:TRUE, nosh:TRUE);
    product = eregmatch(string:output, pattern:'Product: (.+)');

    if (!isnull(product))
    {
      if (product[1] =~ 'IronPort.+Web Security (Virtual )?Appliance' || product[1] =~ 'Cisco.+Web Security (Virtual )?Appliance')
        product = 'Cisco Web Security Appliance';
      else if (product[1] =~ 'IronPort.+Messaging Gateway' || product[1] =~ 'Cisco.+Email Security (Virtual )?Appliance')
        product = 'Cisco Email Security Appliance';
      else if (product[1] =~ 'IronPort.+Security Management' || product[1] =~ 'Cisco.+Content Security (Virtual )?Management Appliance')
        product = 'Cisco Content Security Management Appliance';
      else
      {
        # unknown AsyncOS product
        report += '\nLocal security checks have NOT been enabled for ' + product[1] + '.\n';
        security_note(port:0, extra:report);
        exit(0);
      }

      _local_checks_enabled();
      set_kb_item(name:'Host/AsyncOS/' + product, value:TRUE);
      set_kb_item(name:'Host/AsyncOS/version_cmd', value:output);
      report += '\nLocal security checks have been enabled for ' + product + '.\n';
      security_note(port:0, extra:report);
      exit(0);
    }

  }
  else if ('Command Line Interface is starting up, please wait' >< buf) # Cisco UCOS
  {
    # prompt is 'username:', build a regex that
    # will match the last 5 characters of this prompt
    login = kb_ssh_login();
    if(strlen(login) <= 4)
      last5_prompt = login;
    else last5_prompt = substr(login, strlen(login) - 4, strlen(login) - 1);
    last5_prompt += ':';

    cmd = 'show version active\n';
    show_ver = ssh_cmd(cmd:cmd, last5_prompt:last5_prompt, nosudo:TRUE, nosh:TRUE, noexec:TRUE);

    if (cmd >!< show_ver)
    {
       ssh_close_connection();
       exit(1, 'Unexpected response to "' + chomp(cmd) + '".');
    }

    match = eregmatch(string:show_ver, pattern:'Active Master Version: ([0-9.-]+)');
    if(isnull(match) || isnull(match[1]))
    {
      ssh_close_connection();
      exit(1, 'Unable to find version in output of "' + chomp(output) + '".');
    }

    version = match[1];

    cmd = 'file list activelog /\n';
    files = ssh_cmd(cmd:cmd, last5_prompt:last5_prompt, nosudo:TRUE, nosh:TRUE, noexec:TRUE);

    if(files =~ '<dir>[ \t]*ctms[\n\r <]')
    {
      ssh_close_connection();
      product = 'Cisco TelePresence Multipoint Switch';
    }
    else
    {
      cmd = 'show packages active cupadmin*\n';

      packages = ssh_cmd(cmd:cmd, last5_prompt:last5_prompt, nosudo:TRUE, nosh:TRUE, noexec:TRUE);

      ssh_close_connection();

      if (cmd >!< packages) # the command is echoed in the output
        exit(1, 'Unexpected response to "' + chomp(cmd) + '".');

      if (egrep(string:packages, pattern:'^cupadmin-[0-9.-]+$'))
        product = 'Cisco Unified Presence';
      else
        product = 'Unknown Cisco UCOS Product';
    }

    set_kb_item(name:'Host/UCOS/' + product + '/version', value:version);

    if ('Unknown' >< product)
      security_note(port:0, extra:'\nLocal security checks have NOT been enabled for ' + product + '.\n');
    else
      security_note(port:0, extra:'\nLocal security checks have been enabled for ' + product + '.\n');
    exit(0);
  }
  else set_kb_item(name:"Host/uname", value:buf);
}
else
{
  uname_error = ssh_cmd_error();

  if (info_t == INFO_SSH)
  {
    ssh_close_connection();
    sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
    if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

    if (
      strlen(buf) &&
      strlen(ssh_cmd_error()) == 0 &&
      "Mocana SSH" >< ssh_banner
    )
    {
      # Nortel
      cmd = 'swVersionShow';
      buf = ssh_cmd(cmd:cmd, nosh:TRUE, nosudo:TRUE, noexec:TRUE);

      ssh_close_connection();
      sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

      if (!isnull(buf))
      {
        # Nortel CS Signaling Server
        if ("sse-" >< buf && "Loaded Modules:" >< buf)
        {
          set_kb_item(name:"Host/Nortel_CS/swVersionShow", value:buf);

          os = "Nortel CS Signaling Server";

          # eg, "sse-4.50.88 Wednesday March 01 2006 16:45:39 EST"
          foreach line (split(buf, keep:FALSE))
          {
            match = eregmatch(pattern:"^sse-([0-9](\.[0-9]+)+) ", string:line);
            if (!isnull(match))
            {
              os += " with software version " + match[1];
              break;
            }
          }

          set_kb_item(name:"Host/OS/showver", value:os);
          set_kb_item(name:"Host/OS/showver/Confidence", value:100);
          set_kb_item(name:"Host/OS/showver/Type", value:"embedded");

          report += '\n' + 'Local security checks have NOT been enabled for Nortel CS Signaling Server.\n';
          security_note(port:0, extra:report);
          exit(0);
        }
        else exit(1, "Unknown Nortel behavior.");
      }
    }

    # Check for Alcatel / Lucent TiMOS
    buf = ssh_cmd(cmd:"show version", nosudo:TRUE, nosh:TRUE, noexec:TRUE);
    if (
      buf &&
      "TiMOS-" >< buf &&
      "Alcatel-Lucent" >< buf
    )
    {
      set_kb_item(name:"Host/Alcatel/TiMOS/show_version", value:buf);

      # OS fingerprint info
      os_name = "TiMOS";
      match = eregmatch(pattern:"^TiMOS-([^ ]+) .+ (ALCATEL.+?) Copyright", string:buf);
      if (!isnull(match)) os_name += " " + match[1] + ' on ' + match[2];

      set_kb_item(name:"Host/OS/showver", value:os_name);
      set_kb_item(name:"Host/OS/showver/Confidence", value:100);
      set_kb_item(name:"Host/OS/showver/Type", value:"router");

      # Get update info.
      ssh_close_connection();
      sock_g = ssh_open_connection(exit_on_disconnect:TRUE);
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");

      buf = ssh_cmd(cmd:"show uptime", nosudo:TRUE, nosh:TRUE, noexec:TRUE);
      if (buf && "System Up Time" >< buf)
        set_kb_item(name:"Host/last_reboot", value:buf);

      report += '\n' + 'Local security checks have NOT been enabled for Alcatel-Lucent TiMOS.\n';
      security_note(port:0, extra:report);
      exit(0);
    }
  }

  # Report a failure.
  report +=
'\nHowever, the execution of the command "uname -a" failed, so local security
checks have not been enabled.';

  if (info_t == INFO_SSH)
  {
    if (strlen(uname_error) > 0)
    {
      if (
        "password" >< uname_error &&
        "has expired" >< uname_error
      ) set_kb_item(name:'HostLevelChecks/failure', value:"The password for the user '"+get_kb_item("Secret/SSH/login")+"' has expired and must be changed.");

      report += '\n\nNessus returned the following error message :\n' + uname_error;
    }
  }
  security_note(port:0, extra:report);
  exit(0);
}

report += '\nThe output of "uname -a" is :\n' + buf;

uname_r = info_send_cmd(cmd:"uname -r");
if (uname_r)
{
 uname_r = chomp(uname_r);
 set_kb_item(name:"Host/uname-r", value: uname_r);
}

# Get time of last reboot.
last = info_send_cmd(cmd:"/usr/bin/last reboot 2>/dev/null");
if (last) set_kb_item(name:"Host/last_reboot", value:last);
############################# McAfee SecureOS ###################################
if ("SecureOS" >< buf)
{
  # Get release.
  if (!isnull(uname_r))
  {
    release = "SecureOS-" + uname_r;
    set_kb_item(name:"Host/SecureOS/release", value:release);
  }

  # Switch to admin role.
  cmd = 'srole';
  buf = ssh_cmd(cmd:cmd, noexec:TRUE, nosudo:TRUE, noclose:TRUE);

  # If unable to to elevate privilege, we're done.
  if ("Admn" >!< buf)
  {
    report +=
      "Local security checks have been disabled because it was not possible" +
      "to switch to the admin role via the 'srole' command.";
    set_kb_item(name:'HostLevelChecks/failure', value:"Unable to switch to admin role via 'srole'.");
  }
  else
  {
    # Get package list.
    cmd = "cf package list";
    buf = ssh_cmd(cmd:cmd, noexec:TRUE, nosetup:TRUE, nosudo:TRUE);

    # Check output for expected text.
    if ("Local Packages" >!< buf)
    {
      report +=
        'Local security checks have been disabled because the command \''+cmd+'\'
        failed to produce expected results for some reason.';
      set_kb_item(name:'HostLevelChecks/failure', value:"'"+cmd+"' did not return expected result.");
    }
    else
    {
      report +=
        '\nLocal security checks have been enabled for this host.';
      set_kb_item(name:"Host/SecureOS/pkg_list", value:buf);
      _local_checks_enabled();
    }
  }

  security_note(port:0, extra:report);
  misc_calls_and_exit();
}

############################# FreeBSD ###########################################
if ( "FreeBSD" >< buf )
{
  # freebsd-version gives a more accurate version than uname
  buf2 = info_send_cmd(cmd:"/bin/freebsd-version 2>&1");
  if(!isnull(buf2)) match = pregmatch(pattern:"^([0-9]+\.[^ ]*)", string:chomp(buf2));
  else match = NULL;
  if (!isnull(match) && !ssh_cmd_error())
  {
    release = match[1];
    source = 'freebsd-version';
  }    
  else
  {
    release = ereg_replace(pattern:".*FreeBSD ([0-9]+\.[^ ]*).*", replace:"\1", string:buf);
    source = "uname -a";
  }

 items = split(release, sep:"-", keep:0);
 if ( "p" >< items[2] ) items[2] = ereg_replace(pattern:"p", replace:"_", string:items[2]);
 release = "FreeBSD-" + items[0] + items[2];

 set_kb_item(name:"Host/FreeBSD/release", value:release);
 set_kb_item(name:"Host/FreeBSD/source", value:source);

 report += '\n' + 'The remote FreeBSD system is : ' + items[0]+items[2] +
           '\n' + 'Source : ' + source +
           '\n';

 # Figure out command to use to list packages.
 pkginfo_cmd = "/usr/sbin/pkg_info";
 if (items[0] =~ "^[1-9][0-9]+") pkginfo_cmd = "/usr/sbin/pkg info";
 else if (items[0] =~ "^(8\.[1-9]+|9\.)")
 {
   buf = info_send_cmd(cmd:"/usr/bin/fgrep WITH_PKGNG /etc/make.conf");
   if (buf)
   {
     with_pkgng = FALSE;
     foreach line (split(buf, keep:FALSE))
     {
       # nb: setting the variable to any value, even 'FALSE' or 'NO',
       #     causes it to be treated as set.
       match = eregmatch(pattern:"^[ \t]*WITH_PKGNG[ \t]*=[ \t]*([^ \t]+)[ \t]*$", string:line);
       if (match) with_pkgng = TRUE;
     }
     if (with_pkgng) pkginfo_cmd = "/usr/sbin/pkg info";
   }
 }

 # check firewall rules (ipfw and pf)
 cmd = "/sbin/ipfw list";
 ipfw = info_send_cmd(cmd:cmd+" 2>&1");
 if (
   !isnull(ipfw) &&
   'command not found' >!< tolower(ipfw) &&
   'ipfw: getsockopt(ip_fw_get): protocol not available' >!< tolower(ipfw) &&
   'operation not permitted' >!< tolower(ipfw)
 ) set_kb_item(name:"Host/fwrules/output/"+cmd, value:ipfw);
 else
 {
   errmsg = ssh_cmd_error();
   if (!errmsg)
   {
     if (
       'command not found' >< tolower(ipfw) ||
       'ipfw: getsockopt(ip_fw_get): protocol not available' >< tolower(ipfw) ||
       'operation not permitted' >< tolower(ipfw)
     ) errmsg = ipfw;
     else errmsg = 'The command \'' + cmd + '\' failed to produce any results for some reason.';
   }
   set_kb_item(name:'Host/fwrules/errmsg'+cmd, value:errmsg);
 }

  # Check for NAS4Free which is a FreeBSD distro on which the remaining
  # commands won't work (pfctl is missing and pkg_info returns nothing
  # on a fresh install)
  cmd = 'cat /etc/prd.name';
  prd_name = info_send_cmd(cmd:cmd);
  if (!isnull(prd_name) && "NAS4Free" >< prd_name)
  {
    # Get Version.
    version = NULL;
    release = NULL;
    cmd = 'cat /etc/prd.version';
    buf = info_send_cmd(cmd:cmd);
    if (buf && "prd.version" >!< buf )
    {
      version = chomp(buf);
      # Get Revision.
      cmd = 'cat /etc/prd.revision';
      buf = info_send_cmd(cmd:cmd);
      if (buf && "prd.revision" >!< buf) version += '.' + chomp(buf);
    }

    # Get release name.
    cmd = 'cat /etc/prd.version.name';
    buf = info_send_cmd(cmd:cmd);
    if (buf && "prd.version" >!< buf ) release = chomp(buf) - '- ';

    if (!isnull(version)) set_kb_item(name:"Host/nas4free/version", value:version);
    if (!isnull(release)) set_kb_item(name:"Host/nas4free/release", value:release);

    _local_checks_enabled();
    report += '\nLocal security checks have been enabled for this host.';
    security_note(port:0, extra:report);
    misc_calls_and_exit();
  }

 foreach arg (make_list('rules', 'nat', 'queue'))
 {
   cmd = '/sbin/pfctl -s ' + arg;
   pf = info_send_cmd(cmd:cmd+" 2>&1");
   if (
     !isnull(pf) &&
     'command not found' >!< tolower(pf) &&
     'pfctl: /dev/pf: no such file or directory' >!< tolower(pf) &&
     'operation not permitted' >!< tolower(pf)
   ) set_kb_item(name:'Host/fwrules/output/'+cmd, value:pf);
   else
   {
     errmsg = ssh_cmd_error();
     if (!errmsg)
     {
       if (
         'command not found' >< tolower(pf) ||
         'pfctl: /dev/pf: no such file or directory' >< tolower(pf) ||
         'operation not permitted' >< tolower(pf)
       ) errmsg = pf;
       else errmsg = 'The command \'' + cmd + '\' failed to produce any results for some reason.';
     }
     set_kb_item(name:'Host/fwrules/errmsg'+cmd, value:errmsg);
   }
 }

 buf = info_send_cmd(cmd:pkginfo_cmd);
 # nb: pkgng installs into either /usr/sbin or /usr/local/sbin
 if (!buf && "pkg info" >< pkginfo_cmd)
 {
    pkginfo_cmd = str_replace(find:"/usr/sbin", replace:"/usr/local/sbin", string:pkginfo_cmd);
    buf = info_send_cmd(cmd:pkginfo_cmd);
 }
 if (!buf && "no packages installed" >< ssh_cmd_error())
 {
   buf = ' ';
 }
 if ( ! buf )
 {
    errmsg = ssh_cmd_error();
    if (errmsg)
    {
      report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
    }
    else
    {
      report +=
'Local security checks have been disabled because the command \''+pkginfo_cmd+'\'
failed to produce any results for some reason.';
    }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'"+pkginfo_cmd+"' did not return any result.");
  }
  else {
        buf = str_replace(find:'\t', replace:"  ", string:buf);
        set_kb_item(name:"Host/FreeBSD/pkg_info", value:buf);
        _local_checks_enabled();

        report += '\n' + 'Local security checks have been enabled for this host.' +
                  '\n';
        security_note(port:0, extra:report);
        misc_calls_and_exit();
        }
}

############################# NetBSD ###########################################
else if ( "NetBSD" >< buf )
{
  release = ereg_replace(pattern:".*NetBSD[ ]+.*[ ]+([0-9]+[0-9.]+)[ ]+.*", replace:"\1", string:buf);
  release = "NetBSD-" + release;
  set_kb_item(name:"Host/NetBSD/release", value:release);

  report += '\n' + 'Note, though, that Nessus does not have local, credentialed checks for' +
            '\n' + 'NetBSD security fixes, which typically involve patches to the' +
            '\n' + 'source code or updates to binaries themselves.' +
            '\n';
  security_note(port:0, extra:report);
  exit(0);
}

############################# OpenBSD ###########################################
else if ( "OpenBSD" >< buf )
{
  release = ereg_replace(pattern:".*OpenBSD[ ]+.*[ ]+([0-9]+[0-9.]+)[ ]+.*", replace:"\1", string:buf);
  release = "OpenBSD-" + release;
  set_kb_item(name:"Host/OpenBSD/release", value:release);

  # Get firewall rules.
  cmd = "/sbin/pfctl -sa";
  pfctl = info_send_cmd(cmd:cmd+" 2>&1");
  if (
    !isnull(pfctl) &&
    "Status: " >< pfctl &&
    'FILTER RULES:\n' >< pfctl
  )
  {
    match = egrep(pattern:"Status: Disabled", string:pfctl);
    if (match) set_kb_item(name:'Host/fwrules/errmsg'+cmd, value:match);
    else
    {
      cmd = str_replace(find:"-sa", replace:"-sr", string:cmd);
      rules = strstr(pfctl, 'FILTER RULES:') - 'FILTER RULES:';
      if ('\nSTATES:' >< rules) rules = rules - strstr(pfctl, '\nSTATES:');
      if (strlen(rules)) set_kb_item(name:"Host/fwrules/output/"+cmd, value:rules);
      else set_kb_item(name:'Host/fwrules/errmsg'+cmd, value:"Failed to extract filter rules.");
    }
  }
  else
  {
    errmsg = ssh_cmd_error();
    if (!errmsg)
    {
      if (
        'command not found' >< tolower(pfctl) ||
        'operation not permitted' >< tolower(pfctl)
      ) errmsg = pfctl;
      else errmsg = 'The command \'' + cmd + '\' failed to produce any results for some reason.';
    }
    set_kb_item(name:'Host/fwrules/errmsg'+cmd, value:errmsg);
  }

  report += '\n' + 'Note, though, that Nessus does not have local, credentialed checks for' +
            '\n' + 'OpenBSD security fixes, which typically involve patches to the' +
            '\n' + 'source code.' +
            '\n';
  security_note(port:0, extra:report);
  exit(0);
}

######################## RedHat Linux ###########################################
else if ("Linux" >< buf )
{

  # Determine if KSlpice/uptrack is installed and used for maintaining the kernel
  uptrack_uname_a = info_send_cmd(cmd:"uptrack-uname -a 2>/dev/null");
  if (uptrack_uname_a)
  {
    set_kb_item(name:"Host/uptrack-uname-a", value:chomp(uptrack_uname_a));

    # only need to issue the other commands if "uptrack-uname -a" worked

    uptrack_uname_r = info_send_cmd(cmd:"uptrack-uname -r 2>/dev/null");
    if (uptrack_uname_r)
      set_kb_item(name:"Host/uptrack-uname-r", value:chomp(uptrack_uname_r));

    uptrack_show_installed = info_send_cmd(cmd:"uptrack-show 2>/dev/null");
    if (uptrack_show_installed)
      set_kb_item(name:"Host/uptrack-show-installed", value:chomp(uptrack_show_installed));

    uptrack_show_available = info_send_cmd(cmd:"uptrack-show --available 2>/dev/null");
    if (uptrack_show_available)
      set_kb_item(name:"Host/uptrack-show-available", value:chomp(uptrack_show_available));

    uptrack_disable_file = info_send_cmd(cmd:"ls /etc/uptrack/disable 2>/dev/null");
    if (uptrack_disable_file)
      set_kb_item(name:"Host/uptrack-disable-file", value:chomp(uptrack_disable_file));
  }

  cpu = info_send_cmd(cmd:"uname -m");

  foreach arg (make_list('filter', 'nat', 'mangle'))
  {
    simplecmd = 'iptables -L -n -v -t ' + arg;
    # 2011-01-11: on Ubuntu, "iptables -t nat -L" forces the load of
    # the conntrack modules and changes the firewall for stateless to stateful
    # so we run it only if the modules are already loaded
    if (arg == 'nat')
     cmd = strcat('lsmod | grep -q _conntrack_ipv4 && ', simplecmd);
    # nb: similarly with the iptable_mangle
    else if (arg == 'mangle')
      cmd = strcat('lsmod | grep -q iptable_mangle && ', simplecmd);
    else if (arg == 'filter')
      cmd = strcat('lsmod | grep -q iptable_filter && ', simplecmd);
    else
     cmd = simplecmd;
    iptables = info_send_cmd(cmd:cmd+" 2>&1");
    if (
      !isnull(iptables) &&
      'command not found' >!< tolower(iptables) &&
      'permission denied' >!< tolower(iptables) &&
      'table does not exist' >!< tolower(iptables) &&
      'iptables: not found' >!< tolower(iptables)
    ) set_kb_item(name:'Host/fwrules/output/'+cmd, value:iptables);
    else
    {
      errmsg = ssh_cmd_error();
      if (!errmsg)
      {
        if (
          'command not found' >< tolower(iptables) ||
          'permission denied' >< tolower(iptables) ||
          'table does not exist' >< tolower(iptables) ||
          'iptables: not found' >< tolower(iptables)
        ) errmsg = iptables;
        else errmsg = 'The command \'' + cmd + '\' failed to produce any results for some reason.';
      }
      set_kb_item(name:'Host/fwrules/errmsg/'+cmd, value:errmsg);
    }
  }

  if (cpu)
  {
    cpu = chomp(cpu);
    set_kb_item(name:"Host/cpu", value: cpu);
  }

  # Check for EMC Authentication Manager Appliances
  buf = info_send_cmd(cmd:"cat /opt/rsa/am/utils/etc/patchHistory.dat");
  if (buf)
  {
    emclastpatch = split(buf,sep:'\n',keep:FALSE);
    emclastpatch = emclastpatch[max_index(emclastpatch)-1];
    emclastpatch = eregmatch(string:emclastpatch,pattern:'"version":"([0-9.]+)-build([0-9]+)"');
    if(!isnull(emclastpatch))
    {
      set_kb_item(name:"Host/EMC/AM/Patchlist",value:buf);
      set_kb_item(name:"Host/EMC/AM/Version",value:emclastpatch[1]);
      set_kb_item(name:"Host/EMC/AM/Build",value:emclastpatch[2]);
      _local_checks_enabled();
      emcamdisp = emclastpatch[1];
      buf = eregmatch(string:emcamdisp,pattern:"^(\d+\.\d+)\.(\d+)\.(\d+)\.(\d+)$");
      if(!isnull(buf))
      {
        emcamdisp = buf[1]; # Major.Minor
        if(buf[2] != "0")
          emcamdisp += " SP "+buf[2]; # Service Pack
        if(buf[3] != "0")
          emcamdisp += " Patch "+buf[3];
        if(buf[4] != "0")
          emcamdisp += " Hotfix "+buf[4];
      }
      emcamdisp += " (build "+emclastpatch[2]+")";
      set_kb_item(name:"Host/EMC/AM/DisplayVersion",value:emcamdisp);
      report += '\nLocal security checks have been enabled for the EMC RSA Authentication Manager Appliance.\n';
      report += '\nThe Appliance is running version '+emcamdisp+' of EMC RSA Authentication Manager\n';
      security_note(port:0, extra:report);
      exit(0);
    }
  }

  # Check for various VMware Appliances
  vmappliances = make_array(
    'VMware vCenter Server Appliance', 'VMware vCenter Server Appliance',
    'VMware vCenter Operations Manager', 'VMware vCenter Operations Manager',
    'VMware Studio', 'VMware Studio',
    'vCloud Director', 'VMware vCloud Director',
    'VMware vCenter Support Assistant', 'VMware vCenter Support Assistant',
    'VMware vCenter Orchestrator Appliance', 'VMware vCenter Orchestrator',
    'VMware vRealize Orchestrator Appliance', 'VMware vCenter Orchestrator',
    'vSphere Replication Appliance', 'VMware vSphere Replication',
    'Horizon Workspace', 'VMware Horizon Workspace',
    'WorkspacePortal', 'VMware Workspace Portal',
    'vSphere Data Protection', 'vSphere Data Protection',
    'VMware vRealize Appliance', 'VMware vRealize Automation'
  );
  buf = info_send_cmd(cmd:"cat /opt/vmware/etc/appliance-manifest.xml");
  if (buf)
  {
    foreach vmappliance (keys(vmappliances))
    {
      if (vmappliance >< buf)
      {
        vsa_version = strstr(buf, '<fullVersion>') - '<fullVersion>';
        vsa_version = vsa_version - strstr(vsa_version, '</fullVersion>');
        vsa_version = chomp(vsa_version);

        if (vsa_version =~ '^[0-9\\.]+( Build [0-9]+)?$')
        {
          matches = split(vsa_version, sep:' ', keep:FALSE);
          if ('vCenter Support Assistant' >< vmappliance)
            ver = matches[0];
          else
          {
            if (vmappliance == 'vSphere Data Protection')
              ver = matches[0]; # keep all four levels of ver
            else
            {
              pieces = split(matches[0], sep:'.', keep:FALSE);
              ver = pieces[0];
              if (isnull(pieces[1]))
                ver = ver + '.0';
              else
                ver = ver + '.' + pieces[1];

              if (isnull(pieces[2]))
                ver = ver + '.0';
              else
                ver = ver + '.' + pieces[2];
            }
          }
          set_kb_item(name:"Host/" + vmappliances[vmappliance] + "/Version", value:ver);
          # If we got the build number, save that in the KB
          if (max_index(matches) == 3)
          {
            ver += ' Build ' + matches[2];
            set_kb_item(name:"Host/" + vmappliances[vmappliance] + "/Build", value:matches[2]);
          }
          set_kb_item(name:"Host/" + vmappliances[vmappliance] + "/VerUI", value:ver);
        }
        break;
      }
    }
  }

  buf = info_send_cmd(cmd: "cat /etc/vmware-release");
  if ( "VMware" >< buf )
  {
   is_esx3 = FALSE;
   # nb: override info collected by vmware_vsphere_detect.nbin - it's
   #     possible for that to set this KB even though no patch info
   #     was collected.
   replace_kb_item(name:"Host/VMware/release", value:buf);

   if("VMware ESX Server 3" >< buf)
     is_esx3 = TRUE;

   # nb:
   #  Versions older than ESX 3 are not supported
   #  By default we check if ESX version 3 is installed
   #  if not, we use a command that works with ESX 4.

   if(is_esx3)
     cmd =  "/usr/sbin/esxupdate -l query";
   else
     cmd = "/usr/sbin/esxupdate query -a"; # ESX 4 syntax

   patches = info_send_cmd(cmd:cmd);

   # If we didn't get any patches with 'query -a', try running the
   # command without that option.
   if (
     !is_esx3 &&
     (!patches || "error: no such option" >< patches)
   )
   {
     cmd = "/usr/sbin/esxupdate query";
     patches = info_send_cmd(cmd:cmd);
   }

   if (
    !patches ||
    "/usr/sbin/esxupdate: Permission denied" >< patches
   )
   {
    if ("/usr/sbin/esxupdate: Permission denied" >< patches)
    {
      errmsg = "The user " + get_kb_item("Secret/SSH/login") + " does not have permission to run '/usr/sbin/esxupdate'." + '\n';
    }
    else
    {
      errmsg = ssh_cmd_error();
    }
    if (errmsg)
    {
      set_kb_item(name:'HostLevelChecks/failure', value:errmsg);
      report +=
'
Note that it was not possible to use esxupdate to obtain the list of
installed bulletins because of the following error :

' + errmsg;
    }
    else
    {
      set_kb_item(name:'HostLevelChecks/failure', value:"'" + cmd + "' did not product any results.");
      report +=
'
Note that it was not possible to obtain the list of installed bulletins
because the command \'' + cmd + '\' failed to produce any results for
some reason.';
    }
    security_note(port:0, extra:report);
    exit(0);
   }

   set_kb_item(name: "Host/VMware/esxupdate", value: patches);
   buf = egrep(string: patches, pattern: '^[ \t]*([0-9.-]+|ESXi?[0-9]+-Update[0-9]+)[ \t].*( Update | Full bundle )');
   if (buf)
   {
     last = NULL;
     foreach line (split(buf, keep: 0))
     {
       v = eregmatch(string: line, pattern: '^[ \t]*([^ \t]+)[ \t]');
       if (! isnull(v))
       {
         pkg = v[1];
         if(is_esx3)
         {
                 buf = info_send_cmd(cmd: "/usr/sbin/esxupdate info "+pkg);
                 date = egrep(string: buf, pattern: '^Release Date[ \t]*:', icase: 1);
         }
         else
         {
           buf = info_send_cmd(cmd: "/usr/sbin/esxupdate -b " + pkg + " info");
           date = egrep(string: buf, pattern: '^[ \t]*(Releasedate|Release Date)[ \t]*-', icase: 1);
         }

               if (date)
               {
           if(is_esx3)
           {
             v = eregmatch(string: date, pattern: '^Release Date[ \t]*:[ \t]*(20[0-9][0-9]-[012][0-9]-[0-3][0-9])', icase: 1);
             if (!isnull(v)) date = v[1];
             else date = NULL;
           }
           else
           {
             v = eregmatch(string: date, pattern: '^[ \t]*(Releasedate|Release Date)[ \t]*-[ \t]*(20[0-9][0-9]-[012][0-9]-[0-3][0-9])', icase: 1);
             if (!isnull(v)) date = v[2];
             else date = NULL;
           }
               if (! isnull(date) && (isnull(last) || date > last)) last = date;
               }
       }
     }
     if (last) set_kb_item(name: 'Host/VMware/NewestBundle', value: last);
   }
   buf = info_send_cmd(cmd:"/usr/bin/vmware -v");
   if (buf)
   {
     if (' ESXi ' >< buf) e = 'ESXi';
     else if (' ESX ' >< buf) e = 'ESX';
     v = eregmatch(string:buf, pattern:'^VMware ESX (Server )?([0-9\\.]+)');
     if (v[2] !~ '^3\\.') v[2] = ereg_replace(string:v[2], pattern:'^([0-9]\\.[0-9])([0-9\\.]+)?', replace:'\\1');

     if (!isnull(v))
     {
       set_kb_item(name:'Host/VMware/version', value:e + ' ' + v[2]);
     }
   }

   report += '\nLocal security checks have been enabled for this host.';
   # nb: remove any failure message from the SOAP checks.
   rm_kb_item(name:"HostLevelChecks/failure");
   _local_checks_enabled();
   security_note(port:0, extra:report);
   misc_calls_and_exit();
  }

  buf = info_send_cmd(cmd: "cat /etc/mandrake-release");
  if (buf && "/etc/mandrake-release" >!< buf ) set_kb_item(name: "Host/etc/mandrake-release", value: buf);

  buf = info_send_cmd(cmd: "cat /etc/redhat-release");
  if (buf && "/etc/redhat-release" >!< buf )
  {
    set_kb_item(name: "Host/etc/redhat-release", value: buf);
    has_redhat_release = TRUE;
  }

  release = buf;
  ###################### F5 BIG-IQ / BIG-IP ########################################
  # F5 devices are built on top of Centos, in version < 12 /etc/redhat-release is blank
  # in version >= 12 the Centos version string is retained.
  if (!has_redhat_release || "CentOS" >< buf)
  {
    f5verbuf = info_send_cmd(cmd:"cat /VERSION");
    item = eregmatch(pattern:"(^|\n)[ \t]*Product:[ ]*BIG-I([PQ])[\t \n]", string:f5verbuf, icase:TRUE);
    if (f5verbuf && "BIG-I" >< f5verbuf && !isnull(item) && !isnull(item[2]))
    {
      sys = item[2];
      #Product: BIG-IQ
      #Version: 4.0.0
      #Build: 1114.0
      item = eregmatch(string:f5verbuf, pattern:"[Vv]ersion[ \t]*:[ \t]*([0-9.]+)($|[^0-9.])");

      if (!isnull(item))
      {
        ver = item[1];

        item = eregmatch(string:f5verbuf, pattern:"[Bb]uild[ \t]*:[ \t]*([0-9.]+)($|[^0-9.])");
        # Appending build to BIG-IP versions doesn't make sense with it's version scheme
        if (!isnull(item) && sys == 'Q') ver += '.' + item[1];

        set_kb_item(name:"Host/OS/showver", value:"F5 Networks BIG-I" + sys + " "+ver);
        set_kb_item(name:"Host/OS/showver/Confidence", value:100);

        if (sys == 'P') type = 'load-balancer';
        else type = 'embedded';
        set_kb_item(name:"Host/OS/showver/Type", value:type);

        set_kb_item(name:"Host/BIG-I" + sys + "/version", value:ver);
        # Need this for extra version parsing
        set_kb_item(name:"Host/BIG-I" + sys + "/raw_showver", value:f5verbuf);
        if (sys == 'Q')
        {
          _local_checks_enabled();
          report += '\n' + 'Local security checks have been enabled for F5 Networks BIG-I'+sys+'.' +
                    '\n';
        }
        else
        {
          # For newer BIG-IP systems
          modbuf = info_send_cmd(cmd:"tmsh list /sys provision");
          # For older BIG-IP systems
          if (!modbuf) modbuf = info_send_cmd(cmd:"bigpipe db show | grep -i provision.CPU");
          if (modbuf)
          {
            _local_checks_enabled();
            set_kb_item(name:'Host/BIG-I'+sys+'/raw_modules', value:modbuf);
            report += '\n' + 'Local security checks have been enabled for F5 Networks BIG-I'+sys+'.' +
                      '\n';
          }
          else
          {
            report += '\n' + 'Nessus is unable to perform local, credentialed checks for F5 Networks' +
                      '\n' + 'BIG-I'+sys+' because the account provided is not privileged enough to run'+
                      '\n' + 'commands required for these checks.'+
                      '\n';
          }
        }
        security_note(port:0, extra:report);
        exit(0);
      }
    }
  }

  # Store other vendor info for later.
  if ("McAfee" >< buf) mcafeebuf = buf;
  else if ("XenServer" >< buf) xenserver_release = buf;

  if (
    egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release ([3-7]|2\.1)", string:buf) ||
    egrep(pattern:"^Enterprise Linux (Enterprise|Advanced|Server).*release ([3-7]|2\.1)", string:buf) ||
    egrep(pattern:"Fedora .*", string:buf) ||
    egrep(pattern:"Scientific Linux .*", string:buf)
  )
  {
   rpm_buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");
   rpm_errmsg = ssh_cmd_error();

   # Identify Avaya Communications Systems
   if (check_avaya(redhat_release:release))
   {
     # Remove .AV## from the end and near-end of Avaya-altered packages
     rpm_buf = ereg_replace(string:rpm_buf, pattern:"\.AV[^|\-.]*([|\-.])", replace:"\1");
     rpm_buf = ereg_replace(string:rpm_buf, pattern:"-AV[0-9a-zA-Z]*[\-.]", replace:"-");
     rpm_buf = ereg_replace(string:rpm_buf, pattern:"-AV[0-9a-zA-Z]*\|", replace:"|");
   }

   # Identify Oracle Linux.
   OracleLinux = "";
   if (
     egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release [3-7]", string:buf) ||
     egrep(pattern:"^Enterprise Linux (Enterprise|Advanced|Server).*release [3-7]", string:buf)
   )
   {
     if (buf =~ 'release [3-5]([^0-9]|$)')
       release_file = '/etc/enterprise-release';
     else
       release_file = '/etc/oracle-release';

     buf2 = info_send_cmd(cmd:"cat "+release_file);
     if ("Oracle Linux Server" >< buf2)
     {
       buf = buf2;
       OracleLinux = "Oracle Linux Server";
       replace_kb_item(name:"Host"+release_file, value:buf);
     }
     else if ("Enterprise Linux Enterprise Linux" >< buf2)
     {
       buf = str_replace(string:buf2, find:"Enterprise Linux Enterprise Linux", replace:"Oracle Enterprise Linux");
       buf = ereg_replace(pattern:"^(.+ Enterprise Linux).+(release [0-9].+)", replace:"\1 \2", string:buf);
       if (" Update " >< buf) buf = ereg_replace(pattern:"^(.+ release [0-9]+).+ Update ([0-9]+).*$", replace:"\1.\2", string:buf);
       buf = chomp(buf) + '\n';
       OracleLinux = 'Oracle Enterprise Linux';
       replace_kb_item(name:"Host"+release_file, value:buf);
     }
     else if (buf =~ "^Enterprise Linux Enterprise Linux")
     {
       buf = str_replace(string:buf, find:"Enterprise Linux Enterprise Linux", replace:"Oracle Enterprise Linux");
       OracleLinux = 'Oracle Enterprise Linux';
     }
     else if (strlen(buf2) && egrep(pattern:"^(oraclelinux|enterprise)-release", string:rpm_buf))
     {
       pat = "^oraclelinux-release-([0-9]+)[^-]+-([0-9]+)";
       matches = egrep(pattern:pat, string:rpm_buf);
       if (!matches)
       {
         # nb: the enterprise-release package on EL4 doesn't reflect the update level.
         pat = "^enterprise-release-(5)-([0-9]+)";
         matches = egrep(pattern:pat, string:rpm_buf);
       }

       if (matches)
       {
         foreach line (split(matches))
         {
           match = eregmatch(pattern:pat, string:line);
           if (!isnull(match))
           {
             ver = match[1] + '.' + match[2];
             if (int(match[1]) < 6)
             {
               OracleLinux = "Oracle Enterprise Linux";
               replace_kb_item(name:"Host"+release_file, value:'Oracle Enterprise Linux ' + ver + ' (generated from rpm)\n');
             }
             else
             {
               OracleLinux = "Oracle Linux Server";
               replace_kb_item(name:"Host"+release_file, value:'Oracle Linux Server ' + ver + ' (generated from rpm)\n');
             }
             break;
           }
         }
       }
       buf = str_replace(string:buf2, find:"Enterprise Linux Enterprise Linux", replace:"Oracle Enterprise Linux");
       buf = ereg_replace(pattern:"^(.+ Enterprise Linux).+(release [0-9].+)", replace:"\1 \2", string:buf);
       if (" Update " >< buf) buf = ereg_replace(pattern:"^(.+ release [0-9]+).+ Update ([0-9]+).*$", replace:"\1.\2", string:buf);
       buf = chomp(buf) + '\n';
       OracleLinux = 'Oracle Enterprise Linux';
       replace_kb_item(name:"Host"+release_file, value:buf);
     }
   }

   replace_kb_item(name:"Host/RedHat/release", value:buf);

   if ("Red Hat" >< buf)
   {
     report += '\nThe remote Red Hat system is :\n' + buf;
     # Store rhn-channel and subscription-manager repos if available
     rhn_channel_list = info_send_cmd(cmd:'rhn-channel -l 2>/dev/null');
     if (
       !isnull(rhn_channel_list) &&
       'command not found' >!< tolower(rhn_channel_list) &&
       'operation not permitted' >!< tolower(rhn_channel_list) &&
       'username:' >!< tolower(rhn_channel_list)
     ) set_kb_item(name:'Host/RedHat/rhn-channel-list', value:rhn_channel_list);
     subscription_manager_list = info_send_cmd(cmd:'subscription-manager --installed list 2>/dev/null');
     if (
       !isnull(subscription_manager_list) &&
       'command not found' >!< tolower(subscription_manager_list) &&
       'operation not permitted' >!< tolower(subscription_manager_list) &&
       'username:' >!< tolower(subscription_manager_list)
     ) set_kb_item(name:'Host/RedHat/subscription-manager-list', value:subscription_manager_list);

     # Store results of "yum updateinfo list security updates" if available
     # Have to determine RHEL level first, security plugin not needed for RHEL 7+
     #rhel_pattern = "Red Hat Enterprise Linux.*release (\d+)(\D|$)";
     #if ( egrep(pattern:rhel_pattern, string:release) )
     #{
     #  regex_results = eregmatch(pattern:rhel_pattern, string:release);
     #  if (!isnull(regex_results))
     #  {
     #    rhel_num =  int(regex_results[1]);
     #  }
     #}
     #yum_updateinfo = info_send_cmd(cmd:'yum updateinfo list security updates 2>/dev/null');
     #if (
     #  !isnull(yum_updateinfo) &&
     #  'updateinfo list done' >< tolower(yum_updateinfo) &&
     #  'command not found' >!< tolower(yum_updateinfo) &&
     #  'system is not registered' >!< tolower(yum_updateinfo) &&
     #  'operation not permitted' >!< tolower(yum_updateinfo) &&
     #  ( egrep(pattern:"^(Loaded plugins|\s*):.*security(,|$)", string:yum_updateinfo, icase:TRUE) ||
     #    (!isnull(rhel_num) && rhel_num > 6 ) )
     #)
     #{
     #  set_kb_item(name:'Host/RedHat/yum-updateinfo', value:yum_updateinfo);
     #}
     #else if (!isnull(yum_updateinfo))
     #{
     #  set_kb_item(name:'Host/RedHat/yum-updateinfo-error', value:yum_updateinfo);
     #}
   }
   else if ("Fedora " >< buf) report += '\nThe remote Fedora system is :\n' + buf;
   else if (strlen(OracleLinux))
   {
     replace_kb_item(name:"Host/OracleLinux", value:TRUE);
     report += '\nThe remote '+OracleLinux+' system is :\n' + buf;
   }
   else if ("Scientific Linux " >< buf) report += '\nThe remote Scientific Linux system is :\n' + buf;

   # calculate redhat minor version
   # RHEL 3.x
   rh_array = eregmatch(pattern:"(Red Hat Enterprise|Oracle|Oracle Enterprise|Scientific) Linux.*release 3 .*pdate (\d+).*", string:buf);
   if (rh_array) set_kb_item(name:"Host/RedHat/minor_release", value:rh_array[1]);
   # RHEL 4.x
   rh_array = eregmatch(pattern:"(Red Hat Enterprise|Oracle|Oracle Enterprise|Scientific) Linux.*release 4 .*pdate (\d+).*", string:buf);
   if (rh_array) set_kb_item(name:"Host/RedHat/minor_release", value:rh_array[2]);
   # RHEL x.x
   rh_array = eregmatch(pattern:"(Red Hat Enterprise|Oracle|Oracle Enterprise|Scientific) Linux.*release \d+\.(\d+).*", string:buf);
   if (rh_array) set_kb_item(name:"Host/RedHat/minor_release", value:rh_array[2]);

   if ( ! rpm_buf )
   {
     if (rpm_errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + rpm_errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'rpm
-qa\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }

   report += '\nLocal security checks have been enabled for this host.';
   # nb: override any info collected from a Satellite server.
   replace_kb_item(name:"Host/RedHat/rpm-list", value:rpm_buf);
   if ( ! cpu )
   {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'uname
-m\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'uname -m' did not return any result");
    exit(0);
   }
   _local_checks_enabled();
   security_note(port:0, extra:report);
   misc_calls_and_exit();
  }
##################### CentOS #####################
 else if ( "CentOS" >< buf )
 {
   release = buf;
   replace_kb_item(name:"Host/CentOS/release", value:buf);
   report += '\nThe remote CentOS system is :\n' + buf;

   buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");
   if ( ! buf )
   {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'rpm
-qa\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }

   # Identify Avaya Communications Systems
   if (check_avaya(redhat_release:release))
   {
     # Remove .AV## from the end and near-end of Avaya-altered packages
     # This time around, the rpm-list is being stored in buf
     buf = ereg_replace(string:buf, pattern:"\.AV[^|\-.]*([|\-.])", replace:"\1");
     buf = ereg_replace(string:buf, pattern:"-AV[0-9a-zA-Z]*[\-.]", replace:"-");
     buf = ereg_replace(string:buf, pattern:"-AV[0-9a-zA-Z]*\|", replace:"|");
   }

   # nb: override any info collected from a Satellite server.
   replace_kb_item(name:"Host/CentOS/rpm-list", value:buf);
   if (uname_r && ereg(string: uname_r, pattern:"^2\.[0-6]\.[0-9]+(-[0-9]+)?\.el[0-9]*$", icase: 1))
     set_kb_item(name: "Host/rpm/running-kernel", value: "kernel-"+uname_r);
   if ( ! cpu )
   {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'uname
-m\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'uname -m' did not return any result");
    exit(0);
   }
   report += '\nLocal security checks have been enabled for this host.';
   _local_checks_enabled();

   security_note(port:0, extra:report);
   misc_calls_and_exit();
 }
##################### EulerOS #####################
 else if ( "EulerOS" >< buf )
 {
   release = buf;
   replace_kb_item(name:"Host/EulerOS/release", value:buf);
   report += '\nThe remote EulerOS system is :\n' + buf;

   euler_sp_pattern = "EulerOS release [0-9]+\.[0-9]+ \(SP([0-9]+)\)";
   sp = eregmatch(string: buf, pattern: euler_sp_pattern);
   if (! isnull(sp)) set_kb_item(name: "Host/EulerOS/sp", value: sp[1]);

   # Store rpm-list
   buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");
   if ( ! buf )
   {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'rpm
-qa\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }
   replace_kb_item(name:"Host/EulerOS/rpm-list", value:buf);
   # A 32-bit version of EulerOS does not exist at this time.
   if (uname_r && ereg(string: uname_r, pattern:"^[234]\.[0-9]+\.[0-9]+-([0-9]+\.)*[0-9]+\.x86_64(\D|$)", icase: 1))
     set_kb_item(name: "Host/rpm/running-kernel", value: "kernel-"+uname_r);
   if ( ! cpu )
   {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'uname
-m\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'uname -m' did not return any result");
    exit(0);
   }
   report += '\nLocal security checks have been enabled for this host.';
   _local_checks_enabled();

   security_note(port:0, extra:report);
   misc_calls_and_exit();
 }
##################### Virtuozzo #####################
 else if ( "Virtuozzo" >< buf )
 {
   release = buf;
   replace_kb_item(name:"Host/Virtuozzo/release", value:buf);
   report += '\nThe remote Virtuozzo system is :\n' + buf;

   virtuozzo_minor_pattern = "Virtuozzo Linux release [0-9]+\.([0-9]+)(\D|$)";
   minor = pregmatch(string: buf, pattern: virtuozzo_minor_pattern);
   if ( !isnull(minor) && !isnull(minor[1]) && strlen(minor[1]) ) set_kb_item(name: "Host/Virtuozzo/minor_release", value: minor[1]);

   # Store results of "readykernel info" if available
   # Should always have a result on Virtuozzo machines, and even if it doesn't,
   # only affects whether or not we discover the readykernel-patch level.
   readykernel_info = info_send_cmd(cmd:'readykernel info 2>/dev/null');
   if ( !isnull(readykernel_info) && strlen(readykernel_info) )
   {
     set_kb_item(name:'Host/readykernel-info', value:readykernel_info);
     # Patch name: readykernel-patch-20.18-8.0-1.vl7
     readykernel_patch_pattern = '(Patch name|Installed package): (.*?)\n';
     patch_level = pregmatch(string: readykernel_info, pattern: readykernel_patch_pattern);
     if ( !isnull(patch_level) && !isnull(patch_level[2]) && strlen(patch_level[2]) ) set_kb_item(name: "Host/readykernel-patch-level", value: patch_level[2]);
     # Status Details:      Subscription is current
     readykernel_licinfo = info_send_cmd(cmd:'readykernel licinfo 2>/dev/null');
     if ( !isnull(readykernel_licinfo) && strlen(readykernel_licinfo) )
     {
       readykernel_status_pattern = 'Status Details: *(.*?)\n';
       readykernel_lic_status = pregmatch(string: readykernel_licinfo, pattern: readykernel_status_pattern);
       if ( !isnull(readykernel_lic_status) && !isnull(readykernel_lic_status[1]) && strlen(readykernel_lic_status[1]) ) {
         set_kb_item(name: "Host/readykernel-licinfo", value: readykernel_lic_status[1]);
       } else {
         set_kb_item(name: "Host/readykernel-licinfo", value: readykernel_licinfo);
       }
     }
   }

   # Store rpm-list
   buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");
   if ( ! buf )
   {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'rpm
-qa\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }
   replace_kb_item(name:"Host/Virtuozzo/rpm-list", value:buf);
   # Not believed at this time that there exists a 32 bit version of Virtuozzo
   if (uname_r && ereg(string: uname_r, pattern:"^[234]\.[0-9]+\.[0-9]+-([0-9]+\.)*[0-9]+\.vz[0-9]+([0-9]+\.)*[0-9]+(\D|$)", icase: 1))
     set_kb_item(name: "Host/rpm/running-kernel", value: "kernel-"+uname_r);
   if ( ! cpu )
   {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'uname
-m\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'uname -m' did not return any result");
    exit(0);
   }
   report += '\nLocal security checks have been enabled for this host.';
   _local_checks_enabled();

   security_note(port:0, extra:report);
   misc_calls_and_exit();
 }
##################### OracleVM #####################
 else if (egrep(pattern:"Oracle VM server release [0-9]+\.[0-9]+", string:buf))
 {
   match = eregmatch(pattern:"Oracle VM server release ([0-9]+(\.[0-9]+)+)", string:buf);
   replace_kb_item(name:"Host/OracleVM/release", value:"OVS"+match[1]);

   report += '\n' + 'The remote Oracle VM system is : OVS' + match[1] +
             '\n';

   buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");
   if ( ! buf )
   {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'rpm
-qa\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }
   replace_kb_item(name:"Host/OracleVM/rpm-list", value:buf);

   if (uname_r && ereg(string: uname_r, pattern:"^2\.[0-6]\.[0-9]+(-[0-9]+)?\.el[0-9]*$", icase: 1))
     set_kb_item(name: "Host/rpm/running-kernel", value: "kernel-"+uname_r);
   if ( ! cpu )
   {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'uname
-m\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'uname -m' did not return any result");
    exit(0);
   }

   report += '\n' + 'Local security checks have been enabled for this host.\n';

   _local_checks_enabled();
   security_note(port:0, extra:report);
   misc_calls_and_exit();
 }

##################### Junos Space Appliance ########################################
 else if (egrep(pattern:"Space release [0-9][0-9.]+([^0-9.][0-9.]+)? \((dev.)?[0-9]+\)", string:buf))
 {
   match = eregmatch(pattern:"Space release ([0-9][0-9.]+([^0-9.][0-9.]+)?) \((dev.)?([0-9]+)\)", string:buf);
   replace_kb_item(name:"Host/Junos_Space/release", value:"Junos Space " + match[1]);
   replace_kb_item(name:"Host/Junos_Space/version", value:match[1]);
   replace_kb_item(name:"Host/Junos_Space/build", value:match[4]);

   report += '\nThe remote Junos Space system is :\n' + match[1] + '\n';

   buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");
   if ( ! buf )
   {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'rpm
-qa\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }
   replace_kb_item(name:"Host/Junos_Space/rpm-list", value:buf);
   report += '\nLocal security checks have been enabled for this host.';
   _local_checks_enabled();
   security_note(port:0, extra:report);
   misc_calls_and_exit();
 }

######################## Juniper NSM ############################################
 else if ("Juniper" >< buf && "NSM" >< buf)
 {
   # Juniper NSM Has to be built on CentOS
   replace_kb_item(name:"Host/CentOS/release", value:buf);

   report += '\nThe remote host is Juniper NSM.\n\n';

   buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");
   if ( ! buf )
   {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'rpm
-qa\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }

   if (uname_r && ereg(string: uname_r, pattern:"^2\.[0-6]\.[0-9]+(-[0-9.]+)?\.el[0-9]\w*$", icase: 1))
     set_kb_item(name: "Host/rpm/running-kernel", value: "kernel-"+uname_r);

   replace_kb_item(name:"Host/CentOS/rpm-list", value:buf);
   report += '\nLocal security checks have been enabled for this host.';
   _local_checks_enabled();
   security_note(port:0, extra:report);
   misc_calls_and_exit();
 }

####################### Mandrake ####################################################
#Mandrake Linux release 9.1 (Bamboo) for i586
  else
  {
  #buf = ssh_cmd(socket:sock, cmd:"cat /etc/redhat-release");
  if (("Mandrake Linux" >< buf && "Mandrake Linux Corporate" >!< buf) || "Mandrakelinux" >< buf ||
        "Mandriva Linux release" >< buf || "Mandriva Business Server" >< buf)
  {
   report += '\nThe remote Mandrake system is :\n' + buf;
   version = ereg_replace(pattern:"(Mandrake Linux|Mandrakelinux|Mandriva Linux|Mandriva Business Server) release ([0-9]+(\.[0-9])?) .*", string:egrep(string:buf, pattern:"Mandr(ake|iva)"), replace:"\2");
   release = 'MDK';
   if ('Mandriva Business Server' >< buf)
     release += '-MBS';
   set_kb_item(name:"Host/Mandrake/release", value:release + version);
   #report += '\ndebug:\n' + version;

   buf = info_send_cmd(cmd:"rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");

   if ( ! buf )
   {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'rpm
-qa\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }

   report += '\nLocal security checks have been enabled for this host.';
   set_kb_item(name:"Host/Mandrake/rpm-list", value:buf);
   _local_checks_enabled();
   security_note(port:0, extra:report);
   misc_calls_and_exit();
  }
  }

###################### SuSE ###############################################################

  buf = info_send_cmd(cmd: "cat /etc/SuSE-release 2>/dev/null");
  if ( !isnull(buf) && strlen(buf) )
  {
    set_kb_item(name: "Host/etc/suse-release", value: buf);
  }
  else
  {
    # /etc/SuSE-release will deprecate in future. Try /etc/os-release
    # Only write this in Host/etc/suse-release if it contains suse strings
    buf = info_send_cmd(cmd: "cat /etc/os-release 2>/dev/null");
    if ( !isnull(buf) && strlen(buf) &&
         ( "suse linux" >< tolower(buf) || "SuSE SLES" >< buf ||
           "opensuse" >< tolower(buf) || "Novell Linux Desktop" >< buf ) )
    {
      set_kb_item(name: "Host/etc/suse-release", value: buf);
    }
  }

# SuSE Linux Enterprise Server says:
# SuSE SLES-8 (i386)
# VERSION = 8.1
# SuSE pro says:
# SuSE Linux 9.3 (i586)
# VERSION = 9.3
# Version 10.0 on Live CD says:
# SUSE LINUX 10.0 (i586)
# VERSION = 10.0
# SLES9 says:
# Novell Linux Desktop 9 (i586)
# VERSION = 9
# RELEASE = 9
# SLES10 SP2
# SUSE Linux Enterprise Server 10 (i586)
# VERSION = 10
# PATCHLEVEL = 2
#
  if (buf &&
      ("suse linux" >< tolower(buf) || "SuSE SLES" >< buf ||
       "opensuse" >< tolower(buf) || "Novell Linux Desktop" >< buf))
  {
    suse_label = '';
    suse_label_egrep = egrep(pattern:"^(Novell|(Open)?SuSE)", string:buf, icase:TRUE);
    if ( !isnull(suse_label_egrep) && strlen(suse_label_egrep) )
    {
      suse_label = suse_label_egrep;
    }
    else
    {
      # PRETTY_NAME="openSUSE Leap 42.1 (x86_64)
      suse_label_eregmatch = eregmatch(pattern:'PRETTY_NAME="([^"]+)"',string:buf);
      if ( !isnull(suse_label_eregmatch) && !isnull(suse_label_eregmatch[1]) && strlen(suse_label_eregmatch[1]) )
      {
        suse_label = suse_label_eregmatch[1];
      }
      else
      {
        suse_label = 'UNKNOWN';
      }
    }
    report += '\nThe remote SuSE system is :\n' + chomp(suse_label) + '\n';
    version = '';
    version = egrep(string: buf, pattern: '^VERSION *= *"?[0-9.]+"?$');
    version = chomp(ereg_replace(pattern: "^VERSION *= *", string: version, replace: ""));
    version = ereg_replace(pattern: '"', string: version, replace: "");
    if (! version)
    {
      v = eregmatch(pattern:"SuSE Linux ([0-9]+\.[0-9]) .*",
                    string:egrep(string:buf, pattern:"SuSE ", icase:1),
                    icase:TRUE);
      if (! isnull(v)) version = v[1];
    }
    if (! version)
    {
      report += '\nThis version of SuSE Linux could not be precisely identified;\ntherefore, local security checks have been disabled.';
      security_note(port:0, extra:report);
      set_kb_item(name:'HostLevelChecks/failure', value:"Could not identify the version of the remote SuSE system");
      exit(0);
    }
    patchlevel = egrep(string: buf, pattern: "^PATCHLEVEL *= *[0-9]+");
    if (patchlevel)
    {
      pl = eregmatch(string: chomp(patchlevel), pattern: "^PATCHLEVEL *= *([0-9]+)");
      if (! isnull(pl))
      {
        set_kb_item(name: "Host/SuSE/patchlevel", value: pl[1]);
        if (version)
          report += 'PATCHLEVEL = ' + pl[1] + '\n';
      }

    }
    if (version <= 9)
      replace_kb_item(name:"Host/SuSE/release", value:"SUSE" + version);
    else if ( "SUSE Linux Enterprise Desktop" >< buf)
      replace_kb_item(name:"Host/SuSE/release", value:"SLED" + version);
    else if ( "SUSE Linux Enterprise Server" >< buf )
      replace_kb_item(name:"Host/SuSE/release", value:"SLES" + version);
    else
      replace_kb_item(name:"Host/SuSE/release", value:"SUSE" + version);
    buf = info_send_cmd(cmd:"rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");

   if ( ! buf )
   {
    errmsg = ssh_cmd_error();
    if (errmsg)
    {
      report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
    }
    else
    {
      report +=
'Local security checks have been disabled because the command \'rpm
-qa\' failed to produce any results for some reason.';
    }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
    exit(0);
   }

   if ( ! cpu )
   {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because the command \'uname
-m\' failed to produce any results for some reason.';
     }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'uname -m' did not return any result");
    exit(0);
   }

   report += '\nLocal security checks have been enabled for this host.';
   # nb: override any info collected from a Satellite server.
   replace_kb_item(name:"Host/SuSE/rpm-list", value:buf);
   _local_checks_enabled();
   security_note(port:0, extra:report);
   misc_calls_and_exit();
  }

###################### Gentoo ###############################################

  buf = info_send_cmd(cmd: "cat /etc/gentoo-release");
  if (buf && "/etc/gentoo-release" >!< buf ) set_kb_item(name: "Host/etc/gentoo-release", value: buf);

  if ( buf && "Gentoo" >< buf )
  {
    if ( "Gentoo" >< buf )
      report += '\nThe remote Gentoo system is :\n' + egrep(pattern:"^Gentoo", string:buf);
    release = ereg_replace(pattern:"Gentoo Base System version (([0-9]+\.)*[0-9]+).*",
                             string:egrep(string:buf, pattern:"Gentoo"), replace:"\1");
    # Release does not make much sense on Gentoo
    set_kb_item(name:"Host/Gentoo/release", value: release);

    buf = info_send_cmd(cmd: 'egrep "ARCH=" /etc/make.profile/make.defaults');
    if ( buf )
    {
     buf = ereg_replace(string: buf, pattern: 'ARCH="(.*)"', replace: "\1");
     set_kb_item(name: "Host/Gentoo/arch", value: buf);
    }

    buf = info_send_cmd(cmd: 'readlink /etc/make.profile');
    if (buf)
     set_kb_item(name: "Host/Gentoo/make.profile", value: buf);

    buf = info_send_cmd(cmd: "LC_ALL=C emerge --info");
    if (buf)
    {
      set_kb_item(name: "Host/Gentoo/emerge_info", value: buf);
      portdir = extract_gentoo_portdir(buf: buf);
    }

    buf = info_send_cmd(cmd: "LC_ALL=C cat /etc/make.conf");
    if (buf)
    {
      set_kb_item(name: "Host/etc/make_conf", value: buf);
      if (! portdir || portdir[0] != "/")
        portdir = extract_gentoo_portdir(buf: buf);
    }
    if (portdir)
      set_kb_item(name: "Host/Gentoo/portdir", value: portdir);

    if (! portdir || portdir[0] != "/") portdir = "/usr/portage";
    # Sanitize portdir, just in case...
    portdir = str_replace(find:"'", replace:"'\''", string: portdir);
    buf = info_send_cmd(cmd: "LC_ALL=C cat '"+portdir+"/metadata/timestamp.x'");
    if (buf)
      set_kb_item(name: "Host/Gentoo/timestamp_x", value: buf);

    buf = info_send_cmd(cmd: "LC_ALL=C cat '"+portdir+"/metadata/timestamp'");
    if (buf)
      set_kb_item(name: "Host/Gentoo/timestamp", value: buf);

    # A great idea from David Maciejak:
    # 1. app-portage/gentoolkit is not necessarily installed
    # 2. and this find is quicker than "qpkg -v -I -nc"
    # WARNING! We may catch files like -MERGING-* or *.portage_lockfile
    buf = info_send_cmd(cmd:'find /var/db/pkg/ -mindepth 2 -maxdepth 2 -printf "%P\\n" | sort');
    if (buf)
    {
      report += '\nLocal security checks have been enabled for this host.';
      set_kb_item(name:"Host/Gentoo/qpkg-list", value:buf);
      _local_checks_enabled();
      security_note(port:0, extra:report);

      buf = info_send_cmd(cmd: "find '"+portdir+"/' -wholename '"+portdir+"/*-*/*.ebuild' | sed 's,"+portdir+"/\([^/]*\)/.*/\([^/]*\)\.ebuild$,\1/\2,' | sort");
      if (buf && !ereg(pattern:"^find: .+: No such file or directory", string:buf))
      {
       set_kb_item(name:"Host/Gentoo/ebuild-list", value:buf);
      }
    }
    else
    {
      errmsg = ssh_cmd_error();
      if (errmsg)
      {
        report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
      }
      else
      {
        report +=
'Local security checks have been disabled because Nessus failed to
locate any ebuilds under \'/var/pk/pkg\'.';
      }
     set_kb_item(name:'HostLevelChecks/failure', value:"'find /var/db/pkg/' did not return any result");
     security_note(port:0, extra:report);
    }
    misc_calls_and_exit();
    }

###################### Debian ###############################################
  buf = info_send_cmd(cmd: "cat /etc/debian_version");
  if ( buf && "/etc/debian_version" >!< buf )
  {
    set_kb_item(name: "Host/etc/debian-version", value: buf);

    # Raspbian
    bufpi = info_send_cmd(cmd: 'cat /etc/os-release');
    if ("ID=raspbian" >< bufpi)
    {
      set_kb_item(name:"Host/Raspbian", value:TRUE);
      report += '\nThis is a Raspbian system.\n';
      x = egrep(string: bufpi, pattern: "PRETTY_NAME=");
      if (x) v = split(x, sep:'=');
      if (x && max_index(v) > 0)
        set_kb_item(name:"Host/Raspbian/release", value:v[1]);
      report += '\nLocal security checks have been disabled for this host.';
      security_note(port:0, extra:report);
      misc_calls_and_exit();
    }
  }

  if ( buf && egrep(string:buf, pattern:'^([0-9.]+|testing/unstable|(jessie|lenny|squeeze|stretch|wheezy)/sid)[ \t\r\n]*$'))
  {
    report += '\nThe remote Debian system is :\n' + buf;
    debrel = chomp(buf);
    if (debrel == "testing/unstable") might_be_ubuntu = 1;

    buf = info_send_cmd(cmd:'dpkg-query -W -f \'${db:Status-Abbrev}  ${Package}  ${Version}  ${architecture}  ${binary:summary}\n\'');
    if (buf !~ "^[u,i,r,p,h][n,i,c,u,f,h,W,t](R| )")
    {
      if ( debrel =~ "^[0-3]\." )
        buf = info_send_cmd(cmd:'COLUMNS=160 dpkg -l');
      else
        buf = info_send_cmd(cmd:'COLUMNS=250 dpkg -l|cat');
    }

    if (buf)
    {
       buf2 = info_send_cmd(cmd: 'cat /etc/lsb-release');
       buf3 = info_send_cmd(cmd: 'cat /etc/hipchat-release');
       if ("DISTRIB_ID=Ubuntu" >< buf2 && isnull(buf3))
       {
          set_kb_item(name: "Host/Ubuntu", value: TRUE);
          report += '\nThis is a Ubuntu system\n';
          debrel = NULL;
          x = egrep(string: buf2, pattern: "DISTRIB_RELEASE=");
          if (x) v = split(x, sep: '=');
          if (x && max_index(v) > 0)
           replace_kb_item(name: "Host/Ubuntu/release", value: v[1]);
          if ('DISTRIB_DESCRIPTION=' >< buf2)
          {
             x = egrep(string:buf2, pattern:'DISTRIB_DESCRIPTION=');
             if (x) v = split(x, sep:'=');
             if (x && max_index(v) > 0)
             {
                v[1] = ereg_replace(string:v[1], pattern:'"', replace:'');
                set_kb_item(name:'Host/Ubuntu/distrib_description', value:v[1]);
             }
          }
       }
       else if ("atlassian hipchat" >< tolower(buf3))
       {
          version = pregmatch(string:buf3, pattern:"^Atlassian HipChat ([0-9.]+) \(([0-9.]+)\)");
          set_kb_item(name: "Host/HipChat", value: TRUE);
          set_kb_item(name: "Host/HipChat/version", value: version[1]);
          set_kb_item(name: "Host/HipChat/build", value: version[2]);
          report += '\nThis is a HipChat server ' + version[1] + ' appliance.\n';
       }
       report += '\nLocal security checks have been enabled for this host.';
       replace_kb_item(name:"Host/Debian/dpkg-l", value:buf);
       _local_checks_enabled();
       security_note(port:0, extra:report);
    }
    else
    {
      errmsg = ssh_cmd_error();
      if (errmsg)
      {
        report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
      }
      else
      {
        report +=
'Local security checks have been disabled because the command \'dpkg
-l\' failed to produce any results for some reason.';
      }
     security_note(port:0, extra:report);
     set_kb_item(name:'HostLevelChecks/failure', value:"'dpkg' did not return any result");
    }
    if (debrel)
     replace_kb_item(name:"Host/Debian/release", value: debrel);

   misc_calls_and_exit();
  }

  # Google Container-Optimized OS
  buf = info_send_cmd(cmd:"cat /etc/os-release");
  if (buf && ('NAME="Container-Optimized OS"' >< buf))
  {
    set_kb_item(name: "Host/Container-Optimized OS", value:TRUE);
    report += '\nThis is a Container-Optimized OS system.\n';

    version_id = egrep(string:buf, pattern:"VERSION_ID=");
    if (!isnull(version_id))
    {
      version_id -= "VERSION_ID=";
      build_id = egrep(string:buf, pattern:"BUILD_ID=");
      if (!isnull(build_id))
      {
        build_id -= "BUILD_ID=";
        release = version_id + "." + build_id;
        set_kb_item(name:"Host/Container-Optimized OS/release", value:release);

        os_name = "Container-Optimized OS " + release;
        set_kb_item(name:"Host/OS/showver", value:os_name);
        set_kb_item(name:"Host/OS/showver/Confidence", value:100);
        set_kb_item(name:"Host/OS/showver/Type", value:"hypervisor");
      }
    }

    _local_checks_enabled();
    report += '\n' + 'Local security checks have been enabled for Container-Optimized OS.\n';
    security_note(port:0, extra:report);
    exit(0);
  }

###################### Stonesoft Engine ##############################
  buf = info_send_cmd(cmd:"sg-status");
  if (buf && "Stonesoft" >< buf)
  {
    set_kb_item(name: "Host/Stonesoft/sg-status", value: buf);

    # OS fingerprint info
    os_name = egrep(string:buf, pattern:"Software version:");
    if (!isnull(os_name))
    {
      os_name -= "Software version: ";
      set_kb_item(name:"Host/OS/showver", value:os_name);
      set_kb_item(name:"Host/OS/showver/Confidence", value:100);
      set_kb_item(name:"Host/OS/showver/Type", value:"firewall");
    }

    # Uptime.
    match = eregmatch(pattern:"System startup: (.*)", string:buf);
    if (!isnull(match)) set_kb_item(name:"Host/last_reboot", value:match[1]);

    _local_checks_enabled();
    report += '\n' + 'Local security checks have been enabled for Stonesoft engine.\n';
    security_note(port:0, extra:report);
    exit(0);
  }

###################### Slackware ########################################

  buf = info_send_cmd(cmd: 'cat /etc/slackware-version');
  if (buf && "/etc/slackware-version" >!< buf) set_kb_item(name: "Host/etc/slackware-version", value: buf);

  if ("Slackware" >< buf)
  {
    buf = ereg_replace(string: buf, pattern: "^Slackware +", replace: "");
    report += '\nThe remote Slackware system is :\n' + buf;
    if (buf !~ '^[0-9.]+[ \t\r\n]*$')
    {
      report += '\n' + 'The Slackware version is unknown; therefore, local security checks' +
                '\n' + 'have been disabled.\n';
      security_note(port:0, extra:report);
      set_kb_item(name:'HostLevelChecks/failure', value:"Could not identify the version of the remote Slackware system.");
      exit(0);
    }
    set_kb_item(name:"Host/Slackware/release", value: chomp(buf));

    buf = info_send_cmd(cmd: 'ls -1 /var/log/packages');

    if (buf)
    {
      report += '\nLocal security checks have been enabled for this host.';
      set_kb_item(name:"Host/Slackware/packages", value:buf);
      _local_checks_enabled();
      security_note(port:0, extra:report);
    }
    else
    {
     errmsg = ssh_cmd_error();
     if (errmsg)
     {
       report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
     }
     else
     {
       report +=
'Local security checks have been disabled because Nessus failed to list
packages under \'/var/log/packages\' for some reason.';
     }
    set_kb_item(name:'HostLevelChecks/failure', value:"'/var/log/packages' could not be read");
    security_note(port:0, extra:report);
    }
    misc_calls_and_exit();
  }
###################### Citrix XenServer ###############################################
  if (!isnull(xenserver_release))
  {
    report += '\nThe remote Citrix XenServer system is :\n' + xenserver_release;

    match = eregmatch(string:xenserver_release, pattern:"XenServer release (\d+(?:\.\d+)*)-");
    if (!isnull(match)) replace_kb_item(name:"Host/XenServer/release", value:"XS"+match[1]);

    # Get XenServer data.
    buf = info_send_cmd(cmd:"cat /etc/xensource-inventory");
    if (!buf)
    {
      errmsg = ssh_cmd_error();
      if (errmsg)
      {
        report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
      }
      else
      {
       report +=
'\nLocal security checks have been disabled because Nessus failed to' +
'\nread "/etc/xensource-inventory"';
      }
     security_note(port:0, extra:report);
     set_kb_item(name:'HostLevelChecks/failure', value:"failed to read '/etc/xensource-inventory'");
     exit(0);
    }

    set_kb_item(name:"Host/XenServer/xensource-inventory", value:buf);

    # Get XenServer patch data.
    buf = info_send_cmd(cmd:"xe patch-list");

    if(buf) set_kb_item(name:"Host/XenServer/patch-list", value:buf);
    else
    {
      errmsg = ssh_cmd_error();

      if (errmsg)
      {
        report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;

        security_note(port:0, extra:report);
        set_kb_item(name:'HostLevelChecks/failure', value:"'xe patch-list' returned an error.");
        exit(0);
      }

    }

    buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");
    if (!buf)
    {
      errmsg = ssh_cmd_error();
      if (errmsg)
      {
        report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
      }
      else
      {
       report +=
'Local security checks have been disabled because the command \'rpm
-qa\' failed to produce any results.';
      }
     security_note(port:0, extra:report);
     set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
     exit(0);
    }

    report += '\nLocal security checks have been enabled for this host.';
    # nb: override any info collected from a Satellite server.
    replace_kb_item(name:"Host/XenServer/rpm-list", value:buf);

    _local_checks_enabled();
    security_note(port:0, extra:report);
    misc_calls_and_exit();
  }

  buf = info_send_cmd(cmd: "cat /etc/system-release");
  if (buf && "/etc/system-release" >!< buf ) set_kb_item(name:"Host/etc/system-version", value: buf);

###################### Amazon Linux ###############################################
  if (buf && egrep(string:buf, pattern:'^Amazon Linux AMI release [0-9]'))
  {
    report += '\nThe remote Amazon Linux AMI system is :\n' + buf;

    match = eregmatch(pattern:'^Amazon Linux AMI release ([0-9.]+)', string:buf);
    if (!isnull(match)) replace_kb_item(name:"Host/AmazonLinux/release", value:"ALA"+match[1]);

    buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");
    if (!buf)
    {
      errmsg = ssh_cmd_error();
      if (errmsg)
      {
        report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
      }
      else
      {
       report +=
'Local security checks have been disabled because the command \'rpm
-qa\' failed to produce any results for some reason.';
      }
     security_note(port:0, extra:report);
     set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
     exit(0);
    }

    report += '\nLocal security checks have been enabled for this host.';
    # nb: override any info collected from a Satellite server.
    replace_kb_item(name:"Host/AmazonLinux/rpm-list", value:buf);

    _local_checks_enabled();
    security_note(port:0, extra:report);
    misc_calls_and_exit();
  }

  ###################### McAfee Linux ###############################################
  else if((buf && egrep(string:buf, pattern:"^McAfee Linux OS Server release \d")) || mcafeebuf)
  {
    if (mcafeebuf) buf = mcafeebuf;

    report += '\nThe remote McAfee Linux OS system is :\n' + buf;

    match = eregmatch(pattern:"^McAfee Linux OS Server release (\d+)", string:buf);
    if (!isnull(match)) replace_kb_item(name:"Host/McAfeeLinux/release", value:"MLOS"+match[1]);
    # Look for alternate McAfee Linux info.
    else
    {
      buf = info_send_cmd(cmd: 'cat /.mlos-version');
      match = eregmatch(pattern:"Release: \w+-(\d+)", string:buf);
      if (!isnull(match)) replace_kb_item(name:"Host/McAfeeLinux/release", value:"MLOS"+match[1]);
    }

    # Get McAfee SMG info.
    if ("McAfee E" >< mcafeebuf)
    {
      buf = info_send_cmd(cmd:"cat /.build");
      if (buf && "/.build" >!< buf && "smg" >< buf) replace_kb_item(name:"Host/McAfeeSMG/build-info", value:buf);
    }

    # Get RPM list.
    buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}\n'");
    if (!buf)
    {
      errmsg = ssh_cmd_error();
      if (errmsg)
      {
        report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
      }
      else
      {
       report +=
'Local security checks have been disabled because the command \'rpm
-qa\' failed to produce any results for some reason.';
      }
     security_note(port:0, extra:report);
     set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
     exit(0);
    }

    report += '\nLocal security checks have been enabled for this host.';
    # nb: override any info collected from a Satellite server.
    replace_kb_item(name:"Host/McAfeeLinux/rpm-list", value:buf);

    _local_checks_enabled();
    security_note(port:0, extra:report);
    misc_calls_and_exit();
  }

###################### Trend Micro IWSVA ##########################################
  if (buf && egrep(string:buf, pattern:'IWSVA'))
  {
    report += '\nThe remote Trend Micro IWSVA system is :\n' + buf;
    match = eregmatch(pattern:'^IWSVA release ([0-9.]+)', string:buf);
    if (!isnull(match)) replace_kb_item(name:"Host/TrendMicro/IWSVA/release", value:match[1]);

    # Get full version (with build) in addition to release release
    buf = info_send_cmd(cmd:"/usr/iwss/iwssd -v");
    if (buf && "IWSVA" >< buf)
    {
      replace_kb_item(name:"Host/TrendMicro/IWSVA/show_system_version", value:buf);
    }

    buf = info_send_cmd(cmd: "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'");
    if (!buf)
    {
      errmsg = ssh_cmd_error();
      if (errmsg)
      {
        report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
      }
      else
      {
       report +=
'Local security checks have been disabled because the command \'rpm
-qa\' failed to produce any results.';
      }
     security_note(port:0, extra:report);
     set_kb_item(name:'HostLevelChecks/failure', value:"'rpm -qa' did not return any result");
     exit(0);
    }

    report += '\nLocal security checks have been enabled for this host.';
    # nb: override any info collected from a Satellite server.
    replace_kb_item(name:"Host/TrendMicro/IWSVA/rpm-list", value:buf);

    _local_checks_enabled();
    security_note(port:0, extra:report);
    misc_calls_and_exit();
  }
###################################################################################
  else
  {
    # Cisco TelePresence Conductor
    buf = info_send_cmd(cmd: "cat /tandberg/upgrade/software_version");
    if (buf =~ "^XC[1-9.]+$")
    {
      replace_kb_item(name:"Host/tandberg/upgrade/software_version", value:buf);

      report += '\nThe remote Cisco TelePresence system is :\nCisco TelePresence Conductor ' + buf - 'XC';

      report += '\nLocal security checks have been enabled for this host.';

      _local_checks_enabled();
      security_note(port:0, extra:report);
      misc_calls_and_exit();
    }

    # Cisco TelePresence Video Communication Server (VCS)
    buf = info_send_cmd(cmd: "cat /info/product_info.xml");
    if ("tandberg video communication server" >< tolower(buf))
    {
      buf = info_send_cmd(cmd: "cat /tandberg/upgrade/software_version");
      if (buf =~ "^X[0-9.]+$")
      {
        replace_kb_item(name:"Host/Cisco/TelePresence_VCS/Local/Version", value:chomp(buf));
        report += '\nThe remote Cisco TelePresence system is :\nCisco TelePresence Video Communication Server ' + buf - 'X';
        _local_checks_enabled();

        report += '\nLocal security checks have been enabled for this host.';
        security_note(port:0, extra:report);
        misc_calls_and_exit();
      }
    }
  }

  buf = info_send_cmd(cmd: "cat /etc/Eos-release");
  item = eregmatch(pattern:"^Arista Networks EOS\s*(\d+\.[^\s]+)[\s]*$", string:buf);

  if(!isnull(item) && !isnull(item[1]))
  {
    set_kb_item(name:"Host/etc/Eos-release", value:buf);
    report += '\n' + 'Although local, credentialed checks for Arista EOS are not available,' +
              '\n' + 'Nessus has managed to run commands in support of OS fingerprinting.' +
              '\n' +
              '\n' + '/etc/Eos-release contents:' +
              '\n' + buf;

    set_kb_item(name:"Host/Arista-EOS/Version", value:item[1]);

    security_note(port:0, extra:report);
    misc_calls_and_exit();
  }

  ######################## Other Linux ###########################################
  # We do not support TurboLinux but we can check obsolete versions
  buf = info_send_cmd(cmd: "cat /etc/turbolinux-release");
  if (buf && "/etc/turbolinux-release" >!< buf ) set_kb_item(name: "Host/etc/turbolinux-release", value: buf);

  report += '\n' + 'Local security checks have NOT been enabled because the remote Linux' +
            '\n' + 'distribution is not supported.';
  security_note(port:0, extra:report);
  misc_calls_and_exit();
}

######################## MacOS X ###########################################
else if ("Darwin" >< buf )
 {
  operating_system = info_send_cmd(cmd:'cat /System/Library/CoreServices/SystemVersion.plist');
  lines = split(operating_system, keep:FALSE);
  for ( i = 0 ; i < max_index(lines) ; i ++ )
  {
   if ( lines[i] =~ "<key>ProductVersion</key>")
        {
        operating_system = lines[i+1];
        break;
        }
  }
  if ( operating_system =~ "<string>[0-9.]+</string>" )
  {
   operating_system = ereg_replace(pattern:".*<string>([0-9.]+)</string>.*", string:chomp(operating_system), replace:"\1");
   version = "Mac OS X " + operating_system;
  }
  else
  {
  operating_system = ereg_replace(pattern:"^.*Darwin Kernel Version ([0-9]+\.[0-9]+\.[0-9]+):.*$", string:buf, replace:"\1");
  num = split(operating_system, sep:".", keep:FALSE);
  version = "Mac OS X 10." + string(int(num[0]) - 4) + "." + int(num[1]);
  }

  buf = info_send_cmd(cmd: 'cat /private/etc/sysctl-macosxserver.conf');

  if ( "# /etc/sysctl-macosxserver.conf is reserved " >< buf  ) version = version + " Server";
  set_kb_item(name:"Host/MacOSX/Version", value:version);

  if ( operating_system =~ "^1[0-9]\." )
  {
        buf = info_send_cmd(cmd:'grep -A 1 displayName /Library/Receipts/InstallHistory.plist 2>/dev/null| grep string | sed \'s/<string>\\(.*\\)<\\/string>.*/\\1/g\' | sed \'s/^[      ]*//g\'|tr  -d -c \'a-zA-Z0-9\\n _-\'|sort|uniq');
        buf += info_send_cmd(cmd: 'ls -1 /Library/Receipts|grep -v InstallHistory.plist');
  }
   else
        buf = info_send_cmd(cmd: 'ls -1 /Library/Receipts');

  # check firewall info for ipfw and pf (the latter comes with Lion)
  cmd = "/sbin/ipfw list";
  ipfw = info_send_cmd(cmd:cmd+' 2>/dev/null');
  if (
    !isnull(ipfw) &&
    'command not found' >!< tolower(ipfw) &&
    'operation not permitted' >!< tolower(ipfw)
  ) set_kb_item(name:"Host/fwrules/output/"+cmd, value:ipfw);
  else
  {
    errmsg = ssh_cmd_error();
    if (!errmsg)
    {
      if (
        'command not found' >< tolower(ipfw) ||
        'operation not permitted' >< tolower(ipfw)
      ) errmsg = ipfw;
      else errmsg = 'The command \'' + cmd + '\' failed to produce any results for some reason.';
    }
    set_kb_item(name:'Host/fwrules/errmsg'+cmd, value:errmsg);
  }

  foreach arg (make_list('rules', 'nat', 'queue'))
  {
    cmd = '/sbin/pfctl -s ' + arg;
    pf = info_send_cmd(cmd:cmd+' 2>/dev/null');
    if (
      !isnull(pf) &&
      'command not found' >!< tolower(pf) &&
      'operation not permitted' >!< tolower(pf)
    ) set_kb_item(name:'Host/fwrules/output/' + cmd, value:pf);
    else
    {
      errmsg = ssh_cmd_error();
      if (!errmsg)
      {
        if (
          'command not found' >< tolower(pf) ||
          'operation not permitted' >< tolower(pf)
        ) errmsg = pf;
        else errmsg = 'The command \'' + cmd + '\' failed to produce any results for some reason.';
      }
      set_kb_item(name:'Host/fwrules/errmsg'+cmd, value:errmsg);
    }
  }

  if ( ! buf )
  {
   errmsg = ssh_cmd_error();
   if (errmsg)
   {
     report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
   }
   else
   {
     report +=
'Local security checks have been disabled because Nessus failed to get
the list of installed packages on the remote Mac OS X system for some
reason.';
   }
   security_note(port:0, extra:report);
   set_kb_item(name:'HostLevelChecks/failure', value:"Could not obtain the list of installed packages");
   exit(0);
  }
  set_kb_item(name:"Host/MacOSX/packages", value:buf);

  buf = info_send_cmd(cmd: 'ls -1 /Library/Receipts/boms /private/var/db/receipts /System/Library/Receipts 2>/dev/null | grep \'\\.bom$\'');
  if ( buf ) set_kb_item(name:"Host/MacOSX/packages/boms", value:buf);

  report += '\nLocal security checks have been enabled for this host.';
  _local_checks_enabled();

  buf = info_send_cmd(cmd:'/usr/sbin/scutil --get ComputerName');
  if ( buf ) set_kb_item(name:'Host/MacOSX/ComputerName', value:chomp(buf));

  buf = info_send_cmd(cmd:'/usr/sbin/scutil --get LocalHostName');
  if ( buf ) set_kb_item(name:'Host/MacOSX/LocalHostName', value:chomp(buf));
  security_note(port:0, extra:report);

  misc_calls_and_exit();
 }
######################## Solaris ###########################################
else if ( egrep(pattern:"SunOS.*", string:buf) )
{
 if ( buf =~ "SunOS .* 5\.11 ")
 {
  buf = info_send_cmd(cmd: '/usr/bin/pkg list');
  if ( ! buf )
   {
    errmsg = ssh_cmd_error();
    if (errmsg)
    {
      report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
    }
    else
    {
      report +=
'Local security checks have been disabled because the command \'/usr/bin/pkg
list\' failed to produce any results for some reason.';
    }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'pkg list' failed");
    exit(0);
   }
   cpu = info_send_cmd(cmd:"uname -p");
   if (cpu)
   {
     cpu = chomp(cpu);
     set_kb_item(name:"Host/cpu", value: cpu);
   }
   set_kb_item(name:"Host/Solaris11/pkg-list", value:buf);
   buf = info_send_cmd(cmd: '/usr/bin/pkginfo');
   if ( buf ) set_kb_item(name:"Host/Solaris11/pkginfo", value:buf);
   set_kb_item(name:"Host/Solaris11/Version", value:"5.11");
   buf = info_send_cmd(cmd: '/usr/bin/pkg list -H entire');
   if ( buf )
   {
     buf = ereg_replace(string: buf, pattern: '^entire +', replace: "");
     buf = ereg_replace(string: buf, pattern: ' +...\n', replace: "");
     set_kb_item(name: "Host/Solaris11/release", value: buf);
   }
   report += '\n' + 'Local security checks have been enabled for Solaris 11.';
   _local_checks_enabled();
   security_note(port:0, extra:report);
   misc_calls_and_exit();
 }
 else
 {
 buf = info_send_cmd(cmd: '/usr/bin/showrev -a');
 if ( ! buf || !egrep(pattern:"^Patch:", string:buf) ) buf = info_send_cmd(cmd:'/usr/sbin/patchadd -p');
 if ( ! buf )
 {
  errmsg = ssh_cmd_error();
  if (errmsg)
  {
    report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
  }
  else
  {
    report +=
'Local security checks have been disabled because the command \'showrev
-a\' and \'patchadd -p\' both failed to produce any results for some reason.';
  }
  security_note(port:0, extra:report);
  set_kb_item(name:'HostLevelChecks/failure', value:"'showrev -a' and 'patchadd -p' both failed");
  exit(0);
 }

 set_kb_item(name:"Host/Solaris/showrev", value:buf);

 buf = egrep(pattern:"^Release: ", string:buf);
 buf -= "Release: ";
 set_kb_item(name:"Host/Solaris/Version", value:buf);

 buf = info_send_cmd(cmd: '/usr/bin/pkginfo -x');

 if ( ! buf ) {
   errmsg = ssh_cmd_error();
   if (errmsg)
   {
     report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
   }
   else
   {
     report +=
'Local security checks have been disabled because the command \'pkginfo
-x\' failed to produce any results for some reason.';
   }
  security_note(port:0, extra:report);
  set_kb_item(name:'HostLevelChecks/failure', value:"'pkginfo' failed");
  exit(0);
 }

 # Parse the output of 'pkginfo -x'
 prev = NULL;
 array = make_list();
 new_array = split(buf, sep:'\n', keep:FALSE);

 for (i=0; i<max_index(new_array); i++)
 {
   if (i % 2)
     array = make_list(array, prev + " " + new_array[i]);
   else
   {
     tmp = new_array[i];
     prev = ereg_replace(pattern:"^([^ ]+) .*$", replace:"\1", string:tmp);
   }
 }

 # Save the package info
 foreach line ( array )
 {
  pkg = ereg_replace(pattern:"^([^      ]*).*", replace:"\1", string:line);
  version = ereg_replace(pattern:"^" + pkg + " *\([^)]*\) (.*)", replace:"\1", string:line);
  set_kb_item(name:"Solaris/Packages/Versions/" + pkg, value:version);
 }

  set_kb_item(name:"Host/Solaris/pkginfo", value:buf);
  report += '\nLocal security checks have been enabled for this host.';
  _local_checks_enabled();
  security_note(port:0, extra:report);
  misc_calls_and_exit();
 }
}

############################# AIX ##############################################
else if ( "AIX" >< buf )
{
  release = ereg_replace(pattern:".*AIX[ ]+.*[ ]+([0-9]+[ ]+[0-9]+)[ ]+.*", replace:"\1", string:buf);
  items = split(release, sep:" ", keep:0);
  release = "AIX-" + items[1] + "." + items[0];
  set_kb_item(name:"Host/AIX/version", value:release);

  os_name = str_replace(find:"-", replace:" ", string:release);
  buf = info_send_cmd(cmd: "/usr/bin/oslevel -r");
  if (buf)
  {
    match = eregmatch(pattern:"^([0-9][0-9][0-9][0-9])-([0-9][0-9])$", string:buf);
    if (!isnull(match)) os_name += " TL " + int(match[2]);

    set_kb_item(name:"Host/AIX/oslevel", value:buf);
  }

  buf = info_send_cmd(cmd: "/usr/bin/oslevel -s");
  if (buf)
  {
    match = eregmatch(pattern:"^([0-9][0-9][0-9][0-9])-([0-9][0-9])-([0-9][0-9])-([0-9][0-9][0-9][0-9])$", string:buf);
    if (!isnull(match))
    {
      if (" TL " >!< os_name) os_name += " TL " + int(match[2]);
      os_name += " SP " + int(match[3]);
    }

    set_kb_item(name:"Host/AIX/oslevelsp", value:buf);
  }
  report += '\n' + 'The remote AIX system is : ' + os_name +
            '\n';

  # execute the emgr command and capture the stderr as well as stdout
  buf = info_send_cmd(cmd: "/usr/sbin/emgr -l 2>&1");
  emgr_err_reason = "";
  if ( buf )
  {
    # verify that buf contains appropriate text
    if ( ("There is no efix data on this system." >< buf) || ("INSTALL TIME" >< buf) )
    {
      set_kb_item(name:"Host/AIX/ifixes", value:buf);
    }
    else
    {

      emgr_err_reason =
'The emgr command experienced an error during execution. Verify that
the current user has execute permissions for the emgr command.';
      error_buf = buf;
      if (strlen(error_buf) > 100) error_buf = substr(error_buf, 0, 99);
      emgr_err_reason = emgr_err_reason + " Error message = [" + error_buf + "]";
      set_kb_item(name:'Host/AIX/emgr_failure', value:emgr_err_reason);
    }
  }
  else
  {
    emgr_err_reason =
'The emgr command experienced an error during execution. Verify that
the current user has execute permissions for the emgr command.';
    set_kb_item(name:'Host/AIX/emgr_failure', value:emgr_err_reason);
  }

  buf = info_send_cmd(cmd: "lslpp -Lc");

  if ( ! buf ) {
    errmsg = ssh_cmd_error();
    if (errmsg)
    {
      report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
    }
    else
    {
      report +=
'Local security checks have been disabled because the command \'lslpp
-Lc\' failed to produce any results for some reason.';
    }

    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'lslpp -Lc' failed");
    exit(0);
  }
  set_kb_item(name:"Host/AIX/lslpp", value:buf);
  report += '\n' + 'Local security checks have been enabled for this host.\n';

  # add appropriate error message if there was an issue with emgr command
  if (get_kb_item("Host/AIX/emgr_failure"))
    report += '

iFix checks have been disabled because of the following error :
' + emgr_err_reason;

  # Get processor type
  buf = info_send_cmd(cmd: "prtconf | grep -i 'Processor Type'");
  if ( 'Processor Type' >< buf ) {
    set_kb_item(name:"Host/AIX/processor", value:buf);
  }

  _local_checks_enabled();
  security_note(port:0, extra:report);
  misc_calls_and_exit();
}

############################# HP-UX ##############################################
else if ( "HP-UX" >< buf )
{
  release = ereg_replace(pattern:".*HP-UX[ ]+.*[ ]+B\.([0-9]+\.+[0-9]+)[ ]+.*", replace:"\1", string:buf);
  set_kb_item(name:"Host/HP-UX/version", value:release);

  if ("ia64" >< buf)
  {
    hardware = ereg_replace(pattern:".*HP-UX[ ]+.*[ ]+B\.[0-9]+\.+[0-9]+[ ]+.[ ]+ia64.*", replace:"800", string:buf);
    set_kb_item(name:"Host/HP-UX/processor", value: "ia64");
  }
  else
  {
    hardware = ereg_replace(pattern:".*HP-UX[ ]+.*[ ]+B\.[0-9]+\.+[0-9]+[ ]+.[ ]+[0-9]+/(7|8)[0-9]+.*", replace:"\100", string:buf);
    set_kb_item(name:"Host/HP-UX/processor", value: "parisc");
  }
  set_kb_item(name:"Host/HP-UX/hardware", value:hardware);
  buf = info_send_cmd(cmd:"/usr/sbin/swlist -l fileset -a revision");
  if ( !buf )  {
    errmsg = ssh_cmd_error();
    if (errmsg)
    {
      report +=
'Local security checks have been disabled because of the following
error :

' + errmsg;
    }
    else
    {
      report +=
'Local security checks have been disabled because the command \'swlist -l
fileset -a revision\' failed to produce any results for some reason.';
    }
    security_note(port:0, extra:report);
    set_kb_item(name:'HostLevelChecks/failure', value:"'swlist -l fileset -a revision' failed");
    exit(0);
  }

  set_kb_item(name:"Host/HP-UX/swlist", value:buf);
  report += '\nLocal security checks have been enabled for this host.';
  _local_checks_enabled();
  security_note(port:0, extra:report);
  misc_calls_and_exit();
}
