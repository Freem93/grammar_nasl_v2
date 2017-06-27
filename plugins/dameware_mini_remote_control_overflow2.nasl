#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(19554);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/12/06 20:03:50 $");

 script_cve_id("CVE-2005-2842");
 script_bugtraq_id(14707);
 script_osvdb_id(19119);

 script_name(english:"DameWare Mini Remote Control Pre-Authentication Username Remote Overflow");
 script_summary(english:"Determines version of DameWare Mini Remote Control (Overflow2)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running DameWare Mini Remote Control.  The remote
version of this software is vulnerable to a buffer overflow attack. 
An attacker can exploit this flaw by sending a specially crafted
packet to the remote host.  Successful exploitation of this
vulnerability would result in remote code execution.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.9.0.0 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploithub_sku", value:"EH-11-812");
 script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/31");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:dameware:mini_remote_control");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_require_ports(6129, "Services/dameware");
 script_dependencies("dameware_mini_remote_control_overflow.nasl");
 script_require_keys("DameWare/major_version", "DameWare/minor_version");
 exit(0);
}

port = get_kb_item("Services/dameware");
if (! port) port = 6129;

major = get_kb_item ("DameWare/major_version");
minor = get_kb_item ("DameWare/minor_version");

if (isnull(major) || isnull(minor))
  exit (0);
if (((major == 3) && (minor >= 23920)) || ((major == 4) && (minor < 14745)))
  security_hole(port:port);

