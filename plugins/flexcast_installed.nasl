#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18428);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2011/03/17 11:28:56 $");

  script_name(english:"FlexCast Server Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is an audio / video streaming application." );
 script_set_attribute(attribute:"description", value:
"The remote host is running FlexCast, an audio/video streaming server." );
 script_set_attribute(attribute:"see_also", value:"http://flexcast.virtualworlds.de/" );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this program is in accordance with your corporate
security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/07");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for FlexCast";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8000, 8001);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8000);


# Check the banner for FlexCast.
banner = get_http_banner(port:port);
if (banner && "Server: FlexCast Server/" >< banner)
  security_note(port);
