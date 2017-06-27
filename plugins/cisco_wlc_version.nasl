#TRUSTED 460aa84b5753976faefdd15c1589f41476d0cae4972ed5c4a68cfc4bce0aa51310172447cd0a190e6985bd200d8a27fa9785c32440b78d2defe7f88f85a6eb5648dd8ef35cf499197c3e136a50c2afa68bfc32ddb6ee18a190a9ec526c7dc0a6f0d069d200a13ce447776f56de95941eac0e63038798df794e0188cde3fd5997d77e3cc4e98b4ba978eaaa3c245b447df8633e3abadadf0626495766d582c57569c442a1952e015930309d081758d309c03367c3838beec40a26afff31ff14266644fc613abc62364617d1d7a13d6ef1c55300ef87bc89e46156be9ef29cd3be0b6bc7f9a92d3c274f53af8afeb2c8ed5b58476c2ea29562f5bcf0352feb47db9476d8a1883091e9bdb12a102407ce83a143b2d1b469aa0a42285415d1846994d7243672648698f947bd42f65bfcf4dca611760853656f705d9da6dbfa25e2063d7c39d15d744787866c66845ad1fd72442a0d7fcac7d0eafd54b5c4df1bddea9f3e077168a7e3843b413aec5d1b63432deb5b0bd3306e13f4f19087ffc551bb03e4928c918caaa8a11560c55f486d2c996a849d27b52077a3066c493bb392cddee29247988dbb88fcda93c7b3dda49a72570e707ce58d46780b83a57a2c5e75287ab55f20bc788b0d459d5b13c6c19953a434bfe109ce602f9c7b984f83d4bc082260c378280a20879e67486f64c27c456af560ee7d5bec562cad592ecfad0c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(70122);
 script_version("1.5");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/24");

 script_name(english:"Cisco Wireless LAN Controller (WLC) Version");
 script_summary(english:"Obtains the version of the remote WLC.");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the WLC version of the remote Cisco device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Cisco Wireless LAN Controller (WLC), an
operating system for Cisco switches. It is possible to read the WLC
version by connecting to the switch using SSH, SNMP, and/or CAPWAP.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "capwap_detect.nbin");
 script_require_ports("Host/Cisco/show_ver", "SNMP/sysDesc", "Services/udp/capwap");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("snmp_func.inc");
include("misc_func.inc");

##
# Saves the provided WLC version number in the KB, generates plugin output,
# and exits.  If a model number is provided it is also saved in
# the KB and reported.
#
# @anonparam ver WLC version number
# @anonparam model WLC model number
# @anonparam source protocol used to obtain the version
# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, model, source)
{
  local_var report;

  if (!isnull(model)) set_kb_item(name:"Host/Cisco/WLC/Model", value:model);

  set_kb_item(name:"Host/Cisco/WLC/Version", value:ver);
  set_kb_item(name:"Host/Cisco/WLC/VersionSource", value:source);

  replace_kb_item(name:"Host/Cisco/WLC", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Source  : ' + source +
      '\n  Version : ' + ver;
    if (!isnull(model))
      report += '\n  Model   : ' + model;
    report += '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);

  exit(0);
}

# 1. SSH
wlc_ssh = get_kb_item("Host/Cisco/show_ver");
if (wlc_ssh)
{
  if (get_kb_item("Host/Cisco/WLC"))
  {
    version = eregmatch(string:wlc_ssh, pattern:"Product Version.+ ([0-9][0-9.]+)");

    wlc_ssh_sh_run = get_kb_item("Secret/Host/Cisco/show_running");
    if (wlc_ssh_sh_run)
    {
      model = eregmatch(string:wlc_ssh_sh_run, pattern:"Machine Model[\.\s]*([^\r\n]+)");
      if (!model) model = eregmatch(string:wlc_ssh_sh_run, pattern:"PID:\s*([^,]+)");
    }

    if (!model)
    {
      wlc_ssh_sh_inv = get_kb_item("Host/Cisco/show_inventory");
      if (wlc_ssh_sh_inv)
      {
        model = eregmatch(string:wlc_ssh_sh_inv, pattern:"Machine Model[\.\s]*([^\r\n]+)");
        if (!model) model = eregmatch(string:wlc_ssh_sh_inv, pattern:"PID:\s*([^,]+)");
      }
    }

    if (!isnull(version))
    {
      report_and_exit(ver:version[1], model:model[1], source:'SSH');
      # never reached
    }
  }
}

# 2. SNMP
wlc_snmp = get_kb_item("SNMP/sysDesc");
if (wlc_snmp)
{
  community = get_kb_item("SNMP/community");
  if (community && !model)
  {
    port = get_kb_item("SNMP/port");
    if(!port) port = 161;

    if( get_udp_port_state(port) && (soc = open_sock_udp(port)))
    {
      # Sanity Check. are we looking at a WLC device?
      txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.1.1.0");
      if ( (txt) && (txt =~ "Cisco Controller") )
      {
        # get version
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.10.1");
        if (txt) version = txt;

        # get hardware model
        txt = snmp_request (socket:soc, community:community, oid:"1.3.6.1.2.1.47.1.1.1.1.13.1");
        if (txt)
        {
          model=txt;
        }
      }
    }
  }

  if (!isnull(version))
  {
    report_and_exit(ver:version, model:model, source:'SNMP');
    # never reached
  }
}

# 3. CAPWAP
wlc_capwap = get_kb_item("Services/udp/capwap");
if (wlc_capwap)
{
  vid = 0x409600; # Cisco WLC uses this
  type = 1;  
  sver = get_kb_item('CAPWAP/ac_info/' + vid + '/' + type);
  if(sver)
  {
    sver = hex2raw(s:sver);
    if(sver && strlen(sver) == 4)
    {
      version = ord(sver[0]) + 
              '.' + ord(sver[1]) + 
              '.' + ord(sver[2]) + 
              '.' + ord(sver[3]);
      report_and_exit(ver:version, source:'CAPWAP');
    }
  }
}
 
failed_methods = make_list();
if (wlc_ssh)
  failed_methods = make_list(failed_methods, 'SSH');
if (wlc_snmp)
  failed_methods = make_list(failed_methods, 'SNMP');
if (wlc_capwap)
  failed_methods = make_list(failed_methods, 'CAPWAP');

if (max_index(failed_methods) > 0)
  exit(1, 'Unable to determine Cisco WLC version number obtained via ' + join(failed_methods, sep:'/') + '.');
else
  exit(0, 'The Cisco WLC version is not available (the remote host may not be Cisco WLC).');
