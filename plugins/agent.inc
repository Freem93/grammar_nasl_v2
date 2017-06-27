#TRUSTED a7c92f2c679e55b36582c6ab1a589e144e03107df05505181c7203be58eb8581b75a91453b8ca08d5c5a20b8ad590dc7e8fd92f4fe6a2f2caac8971b771d9ff13ffaa128d40101aa8657d47fb5567ceb6a8432ce23c103dcc6c3c107179024d04d9aed5bbe37d5c6a2718e73fcdbb3b4febdabc875dfb2e7248543b27c90d0ed92eb43540ed0e66ee086742ded7612c778461b71671f73a25b6f149b98652b6d94c05b757492b5993cfac5e18a1ea60e614f2c3df018c6f8206c610ea6c66967afd125aecf8ffabbd3643707759268ae600c5772f2806bb3ca6a67b3b9d4e6e16b3931f242fd1c4d79e9f6af1962bfb6c105958c84a455fabc9044b582168f9f6c53b10b50af6b1a9af8c4123a52f2d95ecd55831b2539586e2ba0b4462483eac20123c6c48e56c691401665cdb55fb3b330b099f7d6a6c46883164dfbc02a1d151b570def13461e4b18d3acf4b26822acba800542d1472d856341c62fdc4544facd289ca203179e3502dad1d65a735f041731000e5ac4c792d01bcff06b2c175ffc91310dc6e744f46e098e31a8b8d48eecb275a1c3324720d8bdcc399f61c5cdb9e8080366bf295236c79bdf5f66313f971acb6aae8ebda0a7e44524985081a38890ab9ab1e9aca31734783f69ec700241a028ccfdb922717904265398fed213656f9eeb34f811dbfec8ec3549b4736e9c3a6ac72d60a9b1114ce011d5024f
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
#
# @NOGPL@
#
# agent.inc
# Revision: 1.3
#

PRODUCT_MAC_AGENT = -4;

#----------------------------------------------------------------#
# Function    : agent_windows                                    #
# Description : Determine if nessusd is a Windows agent          #
# Inputs      : none                                             #
# Return      : TRUE if Windows agent, FALSE for all others      #
# Notes       : Uses environmental information                   #
# Usage       : agent_windows();                                 #
#----------------------------------------------------------------#
function agent_windows()
{
  local_var env;
  env = nasl_environment();
  return (env["product"] == PRODUCT_WIN_AGENT);
}

#----------------------------------------------------------------#
# Function    : agent_unix                                       #
# Description : Determine if nessusd is an OSX/Linux agent       #
# Inputs      : none                                             #
# Return      : TRUE if Unix agent, FALSE for all others         #
# Notes       : Uses environmental information                   #
# Usage       : agent_unix();                                    #
#----------------------------------------------------------------#
function agent_unix()
{
  local_var env;
  env = nasl_environment();
  return (env["product"] == PRODUCT_UNIX_AGENT);
}

#----------------------------------------------------------------#
# Function    : agent                                            #
# Description : Determine if nessusd is a Windows or OSX/Linux   #
#               agent                                            #
# Inputs      : none                                             #
# Return      : TRUE for agents, FALSE for all others            #
# Notes       : Uses environmental information                   #
# Usage       : agent();                                         #
#----------------------------------------------------------------#
function agent()
{
  # This is safer than testing for !PRODUCT_NESSUSD, however it will need to
  # be updated if new agents are added.
  return agent_windows() || agent_unix();
}

#----------------------------------------------------------------#
# Function    : agent_short_name                                 #
# Description : Determine if nessusd is a Windows or OSX/Linux   #
#               agent                                            #
# Inputs      : none                                             #
# Return      : Computer name for Windows host, hostname for     #
#               Unix hosts                                       #
# Notes       : Uses environmental information                   #
# Usage       : agent_short_name();                              #
#----------------------------------------------------------------#
function agent_short_name()
{
  local_var env;
  env = nasl_environment(flags:ENV_HOST);
  if (!isnull(env["hostname"]) &&
      env["hostname"] != "" &&
      env["hostname"] != "localhost" )
    return env["hostname"];
  else
    return FALSE;
}

#----------------------------------------------------------------#
# Function    : agent_fqdn                                       #
# Description : Determine the name of the remote host            #
# Inputs      : none                                             #
# Return      : Computer name plus the AD domain for Windows     #
#               host, FQDN for Unix hosts                        #
#               Unix hosts                                       #
# Notes       : Uses environmental information                   #
# Usage       : agent_fqdn();                                    #
#----------------------------------------------------------------#
function agent_fqdn()
{
  local_var env, fqdn;
  fqdn = "";
  env = nasl_environment(flags:ENV_HOST);

  if (
    !isnull(env["fqdn"]) &&
    env["fqdn"] != "" &&
    env["fqdn"] != "localhost"
  )
    return env["fqdn"];

  # Windows stores information in two different parts of the array
  if (agent_windows())
  {
    if (!isnull(env["hostname"]) &&
        env["hostname"] != "" &&
        env["hostname"] != "localhost")
        fqdn = env["hostname"];
    else
      return fqdn;
  }

  # 1. *nix hosts store the FQDN in domain, Windows will need to append
  # 2. The *nix host must be resolvable via DNS for domain to not be 'localhost'
  if (!isnull(env["domain"]) &&
      env["domain"] != "" &&
      env["domain"] != "localhost" &&
      env["hostname"] != env["domain"])
  {
    # A windows host will already have some data in 'fqdn'
    if (fqdn)
      fqdn += "." + env["domain"];
    else
      fqdn = env["domain"];
  }
  # If fqdn is not set, most likely because env["domain"] is localhost, fall back to
  # the value in env["hostname"].
  else
  {
    fqdn = env["hostname"];
  }

  return fqdn;
}

#----------------------------------------------------------------#
# Function    : agent_get_ip                                     #
# Description : Determine the IP address of the remote host      #
# Inputs      : none                                             #
# Return      : IP address of the agent host or NULL             #
# Notes       : Uses multiple KB values to try and determine the #
#               IP address, preferring the information provided  #
#               by the interfaces first. The fall-backs are      #
#               listening services, and then active connections. #
# Usage       : agent_get_ip();                                  #
#----------------------------------------------------------------#
function agent_get_ip()
{
  local_var ip_addr, interface;
  ip_addr = NULL;
  interface = FALSE;

  if (agent_windows())
    ip_addr =  _agent_get_win_ip();
  else if (agent_unix())
    ip_addr = _agent_get_unix_ip();
  else
    exit(0, "Unknown agent type");

  if (ip_addr)
  {
    interface = TRUE;
    if (!get_kb_item("agent/ip_address_source"))
      set_kb_item(name:"agent/ip_address_source", value:"interface");
  }
  else
    ip_addr = _agent_get_netstat_ip();

  if (ip_addr && !interface)
  {
    if (!get_kb_item("agent/ip_address_source"))
      set_kb_item(name:"agent/ip_address_source", value:"netstat");
  }
  return ip_addr;
}

#----------------------------------------------------------------#
# Function    : _agent_get_unix_ip                               #
# Description : Determine the IP address of the remote Unix host #
# Inputs      : none                                             #
# Return      : IP address of the Unix agent host or NULL        #
# Notes       : Uses Host/ifconfig KB values to determine the IP #
#               address.                                         #
# Usage       : _agent_get_unix_ip();                            #
#----------------------------------------------------------------#
function _agent_get_unix_ip()
{
  local_var ifconfig, ip_address, extract, pat, patterns;
  ip_address = NULL;

  ifconfig = get_kb_item("Host/ifconfig");

  if (!isnull(ifconfig))
  {
    patterns = make_list(# ifconfig
                         "(?<!docker)\d\s+L[^\n]+\s+inet addr:(?!127\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                         # ip addr show
                         "BROADCAST,MULTICAST,UP,LOWER_UP(?:.*)?\n(?:.*)?\n\s+inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/\d{1,2} brd",
                         # OSX ifconfig
                         "inet\s+((?!127.0.0.1)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+netmask",
                         # alternate ip addr show output
                         "\s+inet\s+(?!127\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+netmask"
                        );

    foreach pat (patterns)
    {
      extract = eregmatch(pattern:pat, string:ifconfig);
      if (!isnull(extract))
      {
        ip_address = extract[1];
        break;
      }
    }
  }

 return ip_address;
}

#----------------------------------------------------------------#
# Function    : _agent_get_win_ip                                #
# Description : Determine the IP address of the remote Windows   #
#               host                                             #
# Inputs      : none                                             #
# Return      : IP address of the Windows agent host or NULL     #
# Notes       : Uses Host/SMB/InterfaceList KB value to          #
#               determine the IP address. This KB item is set by #
#               a plugin that requires WMI.                      #
# Usage       : _agent_get_win_ip();                             #
#----------------------------------------------------------------#
function _agent_get_win_ip()
{

 local_var ip_address, extract, kb;
 ip_address = NULL;
 kb = NULL;

 kb = get_kb_item("Host/SMB/InterfaceList");
 if (kb)
 {
    extract = eregmatch(pattern:"IPAddress/IPSubnet = ([0-9.]+)/", string:kb);
    if (!isnull(extract))
        ip_address = extract[1];
 }

 return ip_address;
}

#----------------------------------------------------------------#
# Function    : _agent_get_netstat_ip                            #
# Description : Determine the IP address of the remote host      #
# Inputs      : none                                             #
# Return      : IP address of agent host or NULL                 #
# Notes       : Uses several netstat related KB items to         #
#               determine the IP address. We prefer listening    #
#               services, then active connections.               #
# Usage       : _agent_get_netstat_ip();                         #
#----------------------------------------------------------------#
function _agent_get_netstat_ip()
{
  local_var extract, found,ip_address, item, kb, kb_list, netstats, pat, pats;
  item = NULL;
  ip_address = NULL;
  found = FALSE;
  kb = NULL;

  kb_list = get_kb_list("Netstat/listen-*/tcp4");

  foreach item (kb_list)
  {
    extract = eregmatch(pattern:"([0-9.]+):", string:item);
    if (!isnull(extract) &&
        extract[1] !~ "^127\." &&
        extract[1] != "0.0.0.0")
    {
      ip_address = extract[1];
      found = TRUE;
      break;
    }
  }

  if (!found)
  kb_list = get_kb_list("Netstat/listen-*/udp4");

  foreach item (kb_list)
  {
    extract = eregmatch(pattern:"([0-9.]+):", string:item);
    if (!isnull(extract) &&
        extract[1] !~ "^127\." &&
        extract[1] != "0.0.0.0")
    {
      ip_address = extract[1];
      found = TRUE;
      break;
    }
  }

 # This is a last ditch effort to find ESTABLISHED or TIME_WAIT sessions.
  if (!found)
  {
    netstats = make_list("Host/netstat",
                         "Host/Windows/netstat_an",
                         "Host/Windows/netstat_ano"
                        );

    pats = make_list("(?:TCP|UDP|tcp|udp) +(?!0\.0\.0\.0|127\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,5}",
                     "(?:TCP|tcp|UDP|udp)\s+\d+\s+\d+\s+(?!0\.0\.0\.0|127\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{1,5}");
    foreach item (netstats)
    {
      kb = get_kb_item(item);
      foreach pat (pats)
      {
        extract = eregmatch(pattern:pat, string:kb);
        if (!isnull(extract))
        {
          ip_address = extract[1];
          found = TRUE;
          # breaks the inner loop
          break;
        }
        if (found)
          #breaks the outer loop
          break;
      }
    }
  }

  return ip_address;
}
