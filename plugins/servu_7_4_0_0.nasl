#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35328);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2011/12/09 02:48:39 $");

  script_bugtraq_id(33180);
  script_osvdb_id(51700);
  script_xref(name:"Secunia", value:"33411");

  script_name(english:"Serv-U 7.x < 7.4.0.0 Multiple Command Remote DoS");
  script_summary(english:"Checks Serv-U version");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Serv-U 7.x is earlier than 7.4.0.0, and is
therefore affected by a denial of service vulnerability.  By using a
specially crafted command such as XCRC, STOU, DSIZ, AVBL, RNTO, or
RMDA, it may be possible for an authenticated attacker to render the
FTP server temporarily unresponsive.");
  script_set_attribute(attribute:"see_also", value:"http://www.serv-u.com/releasenotes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Serv-U version 7.4.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

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
  version =~ "^7\." &&
  ver_compare(ver: version , fix: '7.4', strict: FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version +
      '\n  Version source    : ' + source +
      '\n  Fixed version     : 7.4.0.0' +
      '\n';
    security_warning(port: port, extra: report);
  }
  else security_warning(port);
}
else exit(0, "The Serv-U version "+version+" install listening on port "+port+" is not affected.");
