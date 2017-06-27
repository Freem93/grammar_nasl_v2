#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(41980);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2011/12/09 02:48:39 $");

  script_bugtraq_id(36585);
  script_osvdb_id(58459);
  script_xref(name:"Secunia", value:"36873");

  script_name(english:"Serv-U < 9.0.0.1");
  script_summary(english:"Checks Serv-U version");

  script_set_attribute( attribute:"synopsis", value:
"The remote FTP server is affected by multiple vulnerabilities.");
  script_set_attribute( attribute:"description",  value:
"The installed version of Serv-U is earlier than 9.0.0.1 and as such
is reportedly affected by following issues :

  - Provided 'SITE SET' command is enabled, an authorized 
    user may be able to crash the remote FTP server by
    sending a specially crafted 'SITE SET TRANSFERPROGRESS
    ON' command.

  - An unprivileged user may be able to view all drives and
    virtual paths for drive  '\'.");
  script_set_attribute(attribute:"see_also", value:"http://www.serv-u.com/releasenotes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Serv-U version 9.0.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

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

if (version !~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" && version =~ "^9\.0$")
  exit(0, "The Serv-U version, "+version+" on port "+port+" is not granular enough.");

if (ver_compare(ver: version , fix: '9.0.0.1', strict: FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.0.0.1' +
      '\n';
    security_warning(port: port, extra: report);
  }
  else security_warning(port);
}
else exit(0, "The Serv-U version "+version+" install listening on port "+port+" is not affected.");
