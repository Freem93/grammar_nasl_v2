#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71807);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2014-0659");
  script_bugtraq_id(64675, 64776, 65007);
  script_osvdb_id(101653);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum37566");
  script_xref(name:"CISCO-BUG-ID", value:"CSCum43685");
  script_xref(name:"CISCO-BUG-ID", value:"CSCum43693");
  script_xref(name:"CISCO-BUG-ID", value:"CSCum43700");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140110-sbd");

  script_name(english:"ScMM DSL Modem/Router Backdoor Detection");
  script_summary(english:"Detects the ScMM DSL Modem/Router port 32764 backdoor");

  script_set_attribute(attribute:"synopsis", value:"The remote device contains a backdoor.");
  script_set_attribute(attribute:"description", value:
"The remote device is a DSL Modem/Router with a backdoor running on port
32764.  It is possible for an attacker to run arbitrary commands or
access configuration details (including passwords) on the device.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/elvanderb/TCP-32764");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140110-sbd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00871716");
  script_set_attribute(attribute:"solution", value:"Contact the device vendor regarding the availability of an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SerComm Device Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/scmm_backdoor", 32764);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"scmm_backdoor", default:32764, exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

req = "endiantest00" + raw_string(0x00);
send(socket:soc, data:req);

resp = recv(socket:soc, length:12);
close(soc);

if (strlen(resp) < 4) audit(AUDIT_RESP_BAD, port, "ScMM DSL Modem/Router Backdoor probe", "TCP");

sig = substr(resp, 0, 3);
if (sig != "ScMM" && sig != "MMcS") audit(AUDIT_NOT_DETECT, "ScMM DSL Modem/Router Backdoor", port);

if (sig == "MMcS") set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

req = sig + mkdword(1) + mkdword(1) + raw_string(0x00);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);
send(socket:soc, data:req);
resp = recv(socket:soc, length:2048);

if (strlen(resp) < 13) extra = "Nessus was unable to obtain configuration details.";
else
{
  conf = substr(resp, 12);
  conf = str_replace(string:conf, find:raw_string(0x00), replace:'\n  ');
  conf = str_replace(string:conf, find:raw_string(0x01), replace:'\n    ');
  extra = "Nessus was able to obtain the following configuration details:" + '\n  ' + conf;
}

if (report_verbosity > 0) security_hole(port:port, extra:'\n'+extra);
else security_hole(port);
