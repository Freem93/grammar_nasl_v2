#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11154);
 script_version("$Revision: 1.67 $");
 script_cvs_date("$Date: 2016/03/24 16:14:42 $");

 script_name(english:"Unknown Service Detection: Banner Retrieval");
 script_summary(english:"Displays the unknown services banners.");

 script_set_attribute(attribute:"synopsis", value:
"There is an unknown service running on the remote host.");
 script_set_attribute(attribute:"description", value:
"Nessus was unable to identify a service on the remote host even though
it returned a banner of some type.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/11/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Service detection");
 script_dependencies(
   "apcnisd_detect.nasl",
   "alcatel_backdoor_switch.nasl",
   "asip-status.nasl",
   "auth_enabled.nasl",
   "aximilter_detect.nasl",
   "bugbear.nasl",
   "cacam_detect.nasl",
   "cifs445.nasl",
   "cp-firewall-auth.nasl",
   "dcetest.nasl",
   "dns_server.nasl",
   "dotnet_remoting_services_detect.nasl",
   "echo.nasl",
   "find_service1.nasl",
   "find_service2.nasl",
   "flexnet_publisher_detection.nbin",
   "hp_openview_ovalarmsrv.nasl",
   "hp_openview_ovtopmd.nasl",
   "hp_openview_ovuispmd.nasl",
   "hp_data_protector_installed.nasl",
   "ipswitch_imclient_detect.nasl",
   "ipswitch_imserver_detect.nasl",
   "landesk_remote_control_detect.nbin",
   "lisa_detect.nasl",
   "memcached_detect.nasl",
   "mldonkey_telnet.nasl",
   "mssqlserver_detect.nasl",
   "mysql_version.nasl",
   "nagios_statd_detect.nasl",
   "nessus_detect.nasl",
   "PC_anywhere_tcp.nasl",
   "perforce_server_detect.nasl",
   "postfix_policyd_detect.nbin",
   "qmtp_detect.nasl",
   "quote.nasl",
   "radmin_detect.nasl",
   "res_wm_agent_detection.nasl",
   "res_wm_relay_detection.nasl",
   "rpc_portmap.nasl",
   "rpcinfo.nasl",
   "rsh.nasl",
   "rtsp_detect.nasl",
   "sap_router_detect.nbin",
   "SHN_discard.nasl",
   "squeezecenter_cli_detect.nasl",
   "telnet.nasl",
   "tinc_vpn_detect.nbin",
   "veritas_agent_detect.nasl",
   "veritas_netbackup_detect.nasl",
   "veritas_netbackup_vmd_detect.nasl",
   "weblogic_nodemanager_detect.nasl",
   "X.nasl",
   "xmpp_server_detect.nasl",
   "xtel_detect.nasl",
   "xtelw_detect.nasl",
   "zebedee_detect.nasl",
   "zenworks_rma_detect.nasl"
 );
 script_require_ports("Services/unknown");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("dump.inc");

if ( get_kb_item("global_settings/disable_service_discovery") ) exit(0);

port = get_unknown_svc();
if (!port) audit(AUDIT_SVC_KNOWN);

if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
if (port == 139) exit(0, "Port 139 is ignored.");	# Avoid silly messages
if (!service_is_unknown(port: port)) exit(0, "The service listening on port "+port+" is already known.");

a = get_unknown_banner2(port: port, dontfetch: 1);
if (isnull(a)) exit(0, "Did not receive a banner from the service listening on port "+port+".");
banner = a[0]; type = a[1];
if (isnull(banner)) exit(0, "There is no banner from the service listening on port "+port+".");

h = hexdump(ddata: banner);
if( strlen(banner) >= 3 )
{
  # See if the service is maybe SSL-wrapped.
  test_ssl = get_preference("Service Detection[radio]:Test SSL based services");
  encaps = get_port_transport(port);

  if (
    (strlen(test_ssl) && "All" >!< test_ssl) &&
    encaps == ENCAPS_IP &&
    (
      # nb: TLSv1 alert of some type.
      stridx(banner, '\x15\x03\x01\x00\x02') == 0 ||
      # nb: TLSv1 handshake.
      stridx(banner, '\x16\x03\x01') == 0 ||
      # nb: SSLv3 alert of some type.
      stridx(banner, '\x15\x03\x00\x00\x02') == 0 ||
      # nb: SSLv3 handshake.
      stridx(banner, '\x16\x03\x00') == 0 ||
      # nb: SSLv2 alert of some type.
      stridx(banner, '\x80\x03\x00\x00\x01') == 0
    )
  )
  {
    info = '\n' + "The service on this port appears to be encrypted with SSL. If you" +
           '\n' + "would like Nessus to try harder to detect it, change the 'Test SSL" +
           '\n' + "based services' preference to 'All' and re-run the scan." +
           '\n';
  }
  else
  {
    h = str_replace(find:'\n', replace:'\n           ', string:h);
    info = '\n' + 'If you know what this service is and think the banner could be used to' +
           '\n' + 'identify it, please send a description of the service along with the' +
           '\n' + 'following output to svc-signatures@nessus.org :' +
           '\n' +
           '\n' + '  Port   : ' + port +
           '\n' + '  Type   : ' + type +
           '\n' + '  Banner : ' +
           '\n' + h +
           '\n';
  }

  # only one process should be detected per port, but just to be on the safe side
  # this will do a get_kb_list() to ensure the plugin won't fork
  exes = get_kb_list('Host/Listeners/tcp/' + port); # Linux / AIX
  if (isnull(exes))
    exes = get_kb_list('Host/Windows/ListenProcess/tcp/' + port); # Windows

  if (!isnull(exes))
  {
    info +=
      '\nNessus detected the following process listening on this port :\n\n' +
      join(make_list(exes), sep:'\n') +
      '\n';
  }

  security_note(port:port, extra:info);
}
