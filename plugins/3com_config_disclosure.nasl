#
# (C) Tenable Network Security, Inc.
#

# THIS SCRIPT WAS NOT TESTED !
# 
# Ref:
#
# Date: Mon, 24 Mar 2003 16:56:21 +0100 (CET)
# From: Piotr Chytla <pch@isec.pl>
# Reply-To: iSEC Security Research <security@isec.pl>
# To: bugtraq@securityfocus.com, <vulnwatch@vulnwatch.org>
# 
# Thanks to Piotr Chytla (pch@isec.pl) for sending me user_settings.cfg
# privately.
#


include("compat.inc");

if(description)
{
 script_id(11480);
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(7176);
 script_osvdb_id(50430);
 script_xref(name:"Secunia", value:"8402");
 #script_cve_id("CVE-MAP-NOMATCH");
 # NOTE: no CVE id assigned (jfs, december 2003)
 
 script_name(english:"3com RAS 1500 Configuration Disclosure");
 script_summary(english:"Obtains the remote user_settings.cfg");

 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is susceptible to an information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"The remote 3com SuperStack II Remote Access System 1500 discloses
its user configuration (user_settings.cfg) when the file is
requested through the web interface. The file is transmitted in
cleartext and contains the password of the device as well as other
sensitive information.

An attacker may use this flaw to gain the control of this host." );

  script_set_attribute(attribute:"see_also", value:
"http://seclists.org/vulnwatch/2003/q1/147" );
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this host." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/26");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_ATTACK);
 script_family(english:"Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_require_ports(80, "Services/www");
 script_dependencies("http_version.nasl", "no404.nasl");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);


r = http_send_recv3(method: "GET", item:"/user_settings.cfg", port:port);
if (isnull(r)) exit(0);

if(raw_string(0x01, 0xB9, 0x00, 0x0B, 0x01, 0x03, 0x06, 0x01) >< r[1]+r[2] )
 	security_warning(port);
