#TRUSTED 6728e8118ae4944d724455463c78bd099e553c93c8a8813f6aac412a0f715d7ac7ce08427c7c4cc0ab370b5160ff595be6438c00f703c938923ce32420dd44f0a48ea91b79fa8aec0f1f777431f4d03a9c8b6d65d932bff9a159c4d22450b361c41be85d1ac6ae6dac73be336dc77098d304473541de66003f366ba1fcf7d052a1657e1bb4e329fa452f09e83316b0f9ebfc4702fef6aa55142b22317b4620c35b734e3dabe246b9ee4faf5f52f20440d2b8a92ba46b5d9050c79f0c62ed9f783ce21a427ac43404648456da18d9ec511dce05f111d3acc952881c7439256f2a25dd0b98cf1a2fb6dfbd66e2f049fdd62f33dc45c7c08c78d64f24f6c90b70f8954f808805bf8243f4c064ec5bd7c5ac53532faffc57164545ee2196f9fd0d7952555b8b80097d4552f60443f226aa54d88abed90e6395182a7a75b6bf967e8678300f557565f864c23bf8b494a50b0b593f361fdf7a77a11f462a2388b40ad4460713a269e12d77c6cf6c4654bf08684615e027a85063a397da684ec9fb21e4ef99512be80cd31ae95b8f1de9e17c433d0f9b8dcf0aed90811d5ed3a0b48b9372e93aea4a2d569c68755e282d1f00bbdfb42327af63b4efdc07606e15d7346988dc816ccefee219680ef9eab730e7f80c973dc69703595f924f8334b63963f1da3512c893f927a54289d311121a88abe65347d95ccd82ad13a5d1ccfc3dcda0
#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 4200 || NASL_LEVEL == 4400 ) exit(0);

include("compat.inc");

if(description)
{
 script_id(46215);
 script_version("1.9");
 script_set_attribute(attribute:"plugin_modification_date", value: "2016/08/05");
 
 script_name(english:"Inconsistent Hostname and IP Address");
 script_summary(english:"Checks the host name resolves to the host IP.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host's hostname is not consistent with DNS information.");
 script_set_attribute(attribute:"description", value:
"The name of this machine either does not resolve or resolves to a
different IP address. 

This may come from a badly configured reverse DNS or from a host file
in use on the Nessus scanning host. 

As a result, URLs in plugin output may not be directly usable in a web
browser and some web tests may be incomplete.");
 script_set_attribute(attribute:"solution", value:
"Fix the reverse DNS or host file.");
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 script_family(english: "Settings");
 exit(0);
}

include("resolv_func.inc");

ip = get_host_ip();
name = get_host_name();

if (name == ip) exit(0, "No hostname is available.");

if (! is_same_host(a: name, b: ip, fqdn:TRUE))
{
  set_kb_item(name: "DNS/invalid_hostname", value: TRUE);
  ips = fqdn_resolv(name:name, ipv6:TARGET_IS_IPV6, fqdn:TRUE);
  if ( isnull(ips) || max_index(ips) == 0 )
    security_note(port: 0, extra:'The host name \'' + name + '\' does not resolve to an IP address');
  else
    security_note(port: 0, extra:'The host name \'' + name + '\' resolves to ' + ips[0] + ', not to ' + ip );
}
