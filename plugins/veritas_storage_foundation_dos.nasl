#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31862);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2007-4516", "CVE-2008-0638");
  script_bugtraq_id(25778, 27440);
  script_osvdb_id(41977, 41978);

  script_name(english:"Veritas Storage Foundation Multiple Service Remote DoS (SYM08-004)");
  script_summary(english:"Checks version of Veritas Storage Foundation installed");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a denial
of service issue." );
 script_set_attribute(attribute:"description", value:
"Veritas Storage Foundation, a storage management solution from 
Symantec is installed on the remote host.

The installed version is reportedly affected by a denial of service
vulnerability. By sending specially crafted IP packets to TCP port 
4888, an unauthenticated attacker may be able to cause a denial of 
service condition and crash the scheduler service.

In addition the Administration service may also be affected by a heap
overflow vulnerability." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/488435" );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=665
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1ba798b" );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-007" );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2008.02.20.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2008.02.20a.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as discussed in the vendor advisories
above." );
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 119);
 script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:veritas_storage_foundation");

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/15");
 script_cvs_date("$Date: 2016/11/29 20:13:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("veritas_storage_foundation_detect.nasl");
  script_require_keys("VERITAS/VeritasSchedulerService");
  script_require_ports(4888);
  exit(0);
}


include ("byte_func.inc");
include ("smb_func.inc");

port = get_kb_item("VERITAS/VeritasSchedulerService");
if (!port) exit(0);

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

req = ntlmssp_negotiate_securityblob();

len = strlen(req);

# GUID is a character too small

data = 
	mkdword(len) +
	mkdword(0x10) +
	mkdword(0) +
        "{c15f4527-3d6c-167b-f9c2-ca3908613b5}" + mkbyte(0) +
	mkbyte(0) +
	req;


send(socket:soc, data:data);
buf = recv(socket:soc, length:4096);

# unpatched -> {C15F4527-3D6C-167B-F9C2-CA3908613B79}

if ("{C15F4527-3D6C-167B-F9C2-CA3908613B79}" >< buf)
  security_note(port);
