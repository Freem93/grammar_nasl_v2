#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36035);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2009-0967", "CVE-2009-1031");
  script_bugtraq_id(34125, 34127);
  script_osvdb_id(52773, 52900);
  script_xref(name:"EDB-ID", value:"8211");
  script_xref(name:"EDB-ID", value:"8212");
  script_xref(name:"Secunia", value:"34329");

  script_name(english:"Serv-U < 8.0.0.1 Multiple Vulnerabilities (DoS, Traversal)");
  script_summary(english:"Checks Serv-U version");

  script_set_attribute( attribute:"synopsis", value:
"The remote FTP server is affected by multiple vulnerabilities.");
  script_set_attribute( attribute:"description",  value:
"The installed version of Serv-U is earlier than 8.0.0.1 and thus
is reportedly affected by the following issues :

  - A directory traversal vulnerability enables an
    authenticated, remote attacker to create directories
    outside his or her home directory. (CVE-2009-1031)

  - An authenticated, remote attacker can cause the FTP
    service to become saturated for a long period of time
    using a long series of 'SMNT' commands without an
    argument. During this time, new connections would
    not be allowed. (CVE-2009-0967)");
  script_set_attribute(attribute:"see_also", value:"http://www.serv-u.com/releasenotes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Serv-U version 8.0.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("servu_version.nasl");
  script_require_keys("ftp/servu");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


port    = get_ftp_port(default:21);
version = get_kb_item_or_exit('ftp/'+port+'/servu/version');
source  = get_kb_item_or_exit('ftp/'+port+'/servu/source');

if (version !~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" && version =~ "^8\.0$")
  exit(0, "The Serv-U version, "+version+" on port "+port+" is not granular enough.");

if (ver_compare(ver: version , fix: '8.0.0.1', strict: FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.0.1' +
      '\n';
    security_warning(port: port, extra: report);
  }
  else security_warning(port);
}
else exit(0, "The Serv-U "+version+" install listening on port "+port+" is not affected.");
