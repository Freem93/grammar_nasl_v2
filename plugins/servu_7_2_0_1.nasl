#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33937);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2008-3731");
  script_bugtraq_id(30739);
  script_osvdb_id(47589);
  script_xref(name:"Secunia", value:"31461");

  script_name(english:"Serv-U 7.x < 7.2.0.1 SFTP Directory Creation Logging DoS");
  script_summary(english:"Checks Serv-U version");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Serv-U 7.x is earlier than 7.2.0.1 and thus
reportedly contains an SFTP bug in which directory creation and
logging SFTP commands could lead to an application crash.");
  script_set_attribute(attribute:"see_also", value:"http://www.rhinosoft.com/KnowledgeBase/KBArticle.asp?RefNo=1769");
  script_set_attribute(attribute:"see_also", value:"http://www.serv-u.com/releasenotes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Serv-U version 7.2.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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

if (version !~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" && version =~ "^7\.2$")
  exit(0, "The Serv-U version, "+version+" on port "+port+" is not granular enough.");

if (
  version =~ "^7\." &&
  ver_compare(ver: version , fix: '7.2.0.1', strict: FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.2.0.1' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The Serv-U version "+version+" install listening on port "+port+" is not affected.");
