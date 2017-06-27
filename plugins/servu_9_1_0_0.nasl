#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42934);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2009-4006", "CVE-2009-4873");
  script_bugtraq_id(36895, 37051);
  script_osvdb_id(59772, 60427);
  script_xref(name:"Secunia", value:"37228");

  script_name(english:"Serv-U < 9.1.0.0");
  script_summary(english:"Checks Serv-U version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote FTP server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the installed version of Serv-U is earlier
than 9.1.0.0, and therefore affected by the following issues :

  - A boundary error in the web administration interface
    when parsing session cookies can result in a stack-based
    buffer overflow. (CVE-2009-4873)

  - A boundary error in the TEA decoding algorithm can
    result in a stack-based buffer overflow when processing
    a long hexadecimal string. (CVE-2009-4006)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.rangos.de/ServU-ADV.txt");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2009-46/");
  script_set_attribute(attribute:"see_also", value:"http://www.serv-u.com/releasenotes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Serv-U version 9.1.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Rhinosoft Serv-U Session Cookie Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/30");

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

if (
  version =~ "^[6-9]\." &&
  ver_compare(ver: version , fix: '9.1', strict: FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.1.0.0' +
      '\n';
    security_hole(port: port, extra: report);
  }
  else security_hole(port);
}
else exit(0, "The Serv-U version "+version+" install listening on port "+port+" is not affected.");
