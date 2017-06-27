# -*- Fundamental -*-
#
# This NASL script was written by Martin O'Neal of Corsaire 
# (http://www.corsaire.com)
# 
# The script provides basic tftp functionality for use in other scripts...
#
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Corsaire 
# accepts no responsibility for any damage caused by the use or misuse of 
# this information.
#
# GPLv2
# 
# Some code was added by Michel Arboi <mikhail@nessus.org>
#



############## declarations ################


# declare function
function tftp_get(port,path)
{
	# initialise variables
	local_var request_data;
	local_var request_ip;
	local_var request_udp;
	local_var response_udp;
	local_var response_data;
	local_var filter;
	local_var source_port;
	local_var destination_port;
	source_port=23793+int((rand()%6157));
	destination_port=port;
		
	# create request
	request_data=raw_string(0x00,0x01)+path+raw_string(0x00)+'octet'+raw_string(0x00);
	request_ip=forge_ip_packet(ip_hl:5,ip_v:4,ip_tos:0,ip_len:20,ip_id:rand(),ip_off:0,ip_ttl:64,ip_p:IPPROTO_UDP,ip_src:this_host());
	request_udp=forge_udp_packet(ip:request_ip,uh_sport:source_port,uh_dport:destination_port,uh_ulen:8+strlen(request_data),data:request_data);

	# create filter
	filter='udp and dst port '+source_port+' and src host '+get_host_ip();

	# send packet
	response_udp=send_packet(request_udp,pcap_active:TRUE,pcap_filter:filter);	

	# check if response received
	if(response_udp)
	{
		# retrieve udp data
		response_data=get_udp_element(udp:response_udp,element:"data");
		
		# check if udp data is valid positive tftp data response
		if(ord(response_data[0])==0x00 && ord(response_data[1])==0x03 && ord(response_data[2])==0x00 && ord(response_data[3])==0x01)
		{
			# remove tftp protocol header from data
			response_data=substr(response_data,4);
			
			return(response_data);
		}
	}
	
	return NULL;
}



# declare function
function tftp_put(port,path)
{
	# initialise variables
	local_var request_data;
	local_var request_ip;
	local_var request_udp;
	local_var response_udp;
	local_var response_data;
	local_var filter;
	local_var source_port;
	local_var destination_port;
	source_port=32288+int((rand()%7354));
	destination_port=port;
		
	# create request
	request_data=raw_string(0x00,0x02)+path+raw_string(0x00)+'octet'+raw_string(0x00);
	request_ip=forge_ip_packet(ip_hl:5,ip_v:4,ip_tos:0,ip_len:20,ip_id:rand(),ip_off:0,ip_ttl:64,ip_p:IPPROTO_UDP,ip_src:this_host());
	request_udp=forge_udp_packet(ip:request_ip,uh_sport:source_port,uh_dport:destination_port,uh_ulen:8+strlen(request_data),data:request_data);

	# create filter
	filter='udp and dst port '+source_port+' and src host '+get_host_ip();

	# send packet
	response_udp=send_packet(request_udp,pcap_active:TRUE,pcap_filter:filter);	

	# check if response received
	if(response_udp)
	{
		# retrieve udp data
		response_data=get_udp_element(udp:response_udp,element:"data");
		
		# check if udp data is valid positive tftp data response
		if(ord(response_data[0])==0x00 && ord(response_data[1])==0x04 && ord(response_data[2])==0x00 && ord(response_data[3])==0x00)
		{
			return(TRUE);
		}
	}
	
	return NULL;
}

#### Functions added by Michel Arboi <mikhail@nessus.org> ####

# The 1st function is necessary as TFTP is UDP based and not 100% reliable
# All TFTP scripts should call it to test returned data & avoid false alerts
function tftp_ms_backdoor(data, port, file)
{
 if (strlen(data) > 40 && substr(data, 0, 1) == 'MZ')
   if ('\x50\x45\x00\x00' >< data )
     report_tftp_backdoor(port: port, file: file, type: 'MS PE', data: data);
   else if ('This program cannot be run in DOS mode' >< data ||
   	    'This program must be run under Win32' >< data)
     report_tftp_backdoor(port: port, file: file, type: 'MS', data: data);
}

function report_tftp_backdoor(port, file, type, data)
{
 local_var	a, c, k;

 c = tolower(type[0]);
 if (c == 'm' || c == 'a' || c == 'e' || c == 'x') a = 'an '; else a = 'a ';

 security_hole(port: port, proto: 'udp', data: 
'
Synopsis :

The remote host has probably been compromised. 

Description :

A TFTP server is running on this port. However, while trying to 
fetch "'+ file + '", we got '+ a + type + ' executable file. 

Many worms are known to propagate through TFTP.  This is probably a
backdoor. 

Solution : 

Disinfect / reinstall the system.

Risk factor :

Critical / CVSS Base Score : 10.0
(CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C)');
 if (port == 69)
  set_kb_item(name: 'tftp/backdoor', value: TRUE);
 set_kb_item(name: 'tftp/'+port+'/backdoor', value: TRUE);

 if (strlen(data) > 0 )
 {
   k = '/tmp/antivirus/UDP/'+port;
   if (! get_kb_item(k)) set_kb_item(name: k, value: hexstr(data));
 }
 exit(0);
}

