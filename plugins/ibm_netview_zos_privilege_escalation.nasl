#TRUSTED ae0af20179a42b79260db92c7d2dd5161dcd6388485035753a6a4655ff3f2e2c3817a8e1d6d46c10760f0c11686e82c5a8776e4e7dfbd277eaf5e8e72fad8e38383a33f58bfdf2e45c10f8fce9e7ed28ae14d31e0b456c3053a5932a627fe7b4dcc8566ae715a9af6c475f89d8a528ddcd708e1c767fc0bf5fd30ca21c5afd7f6064d04a6855dcec4ccb42971c466840d51bee8f42a13ff5fd24961caa9ccb9d592207afb58c06950d6d42c5c0d47555d81fab16d77996383559be5696c8ef4b2f52028adec8dcb67c3a757c566b71df94322fcdd2fa44db1cc898f2b994e7abb0fa3ba097bacdbd397332e4d5148a0c9a1f0f197da0436b6f741a3d42e504d96d965b9c59742d61bd11baafadba761de3017851108ec7031ad9a275d82c88fb27415b0966bac26f2c0d2eb5aba065dcf55ee6c9d5481bde5cb1fcf672e3a78e0ff50a5ee908eb90ba02ee41d7f7895396a15d16ae2a8186f054a44239241c54141903d59724f8b2f02e07390e93420446086c686b898be1474a1f6ed10115714dadc72fa078db683430aec99e1d47682bf7f889f77bed5c1a2ce25eb7bfa7f3cbba1fca69b900067e91df83d8cae4dd2ad72f7bb606e460f43ff10aefa0e68b084cc292b352bbd3747c576bd66a2506c87fa8fdc66536e6e704977a12df46562de474c87feef5ecca34315f0263abbca1037615ccaecbc0b3951ac2bec12a5e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70173);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/05/24");

  script_cve_id("CVE-2012-5951");
  script_bugtraq_id(57036);
  script_osvdb_id(88725);
  script_xref(name:"IAVA", value:"2013-A-0021");

  script_name(english:"IBM Tivoli NetView for z/OS Privilege Escalation");
  script_summary(english:"Checks NetView version over telnet.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host may be running software with a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to have IBM Tivoli NetView installed that is
affected by a privilege escalation vulnerability. A Unix System
Services authenticated attacker may be able to gain the privileges of
the NetView application.

Note that Nessus has not tested for the issues, but instead has relied
only on the detected version number. Nessus is unable to determine if
the patches for this vulnerability are installed as it does not change
this detected version number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21621163");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/80643");
  script_set_attribute(attribute:"solution", value:"Updates are available from the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_netview");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/telnet", 23);
  script_require_keys("Secret/ClearTextAuth/login", "Secret/ClearTextAuth/pass");
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("telnet_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

login = get_kb_item_or_exit("Secret/ClearTextAuth/login");
password = get_kb_item_or_exit("Secret/ClearTextAuth/pass");

command = "grep VRM /usr/local/Tivoli/bin/generic_unix/TDS/client/lib/nmc.properties";
version_pattern = "=([0-9.]+)";

affected = make_list(
  "1.4",
  "5.1",
  "5.2",
  "5.3",
  "5.4",
  "6.1"
);

port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

res = telnet_negotiate(socket:soc);
res += recv_until(socket:soc, pattern:"login:");
if (isnull(res))
{
  close(soc);
  audit(AUDIT_NO_BANNER, port);
}

send(socket:soc, data:login + '\r\n');
res = recv_until(socket:soc, pattern:"Password:");
if (isnull(res))
{
  close(soc);
  audit(AUDIT_NO_BANNER, port);
}

send(socket:soc, data:password + '\r\n');
res = recv_until(socket:soc, pattern:"(\$|#|>) ");
if (isnull(res))
{
  close(soc);
  audit(AUDIT_NO_BANNER, port);
}

send(socket:soc, data:command + '\r\n');
res = recv_until(socket:soc, pattern:"(\$|#|>) ");
if (isnull(res))
{
  close(soc);
  audit(AUDIT_NOT_INST, "IBM Tivoli NetView for z/OS");
}

version = eregmatch(pattern:version_pattern, string:res);
version = version[1];

if (isnull(version))
  audit(AUDIT_NOT_INST, "IBM Tivoli NetView for z/OS");

report = "";

foreach vuln_ver (affected)
{
  if (ver_compare(ver:version, fix:vuln_ver, strict:FALSE) == 0)
  {
    report += "Version detected: " + version + '\n';
  }
}

if (report == "")
  audit(AUDIT_INST_VER_NOT_VULN, "IBM Tivoli NetView for z/OS", version);

if (report_verbosity > 0)
  security_hole(port:port, extra:report);
else
  security_hole(port:port);
