#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51645);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2010-2703", "CVE-2011-0261", "CVE-2011-0262", "CVE-2011-0263",
                "CVE-2011-0264", "CVE-2011-0265", "CVE-2011-0266", "CVE-2011-0267",
                "CVE-2011-0268", "CVE-2011-0269", "CVE-2011-0270", "CVE-2011-0271");
  script_bugtraq_id(41829,45762);
  script_xref(name:"EDB-ID", value:"17028");
  script_xref(name:"EDB-ID", value:"17038");
  script_osvdb_id(66514,70469,70470,70471,70472,70473,70474,70475);

  script_name(english:"HP OpenView Network Node Manager Remote Execution of Arbitrary Code (HPSBMA02621 SSRT100352)");
  script_summary(english:"Tries to overflow execvp_nc() buffer in webappmon.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that allows remote
code execution.");
  script_set_attribute(attribute:"description", value:
"The version of HP OpenView Network Node Manager installed on the remote
Windows host contains several vulnerabilities that can be exploited
remotely to allow execution of arbitrary code within the context of the
affected web server userid.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-003/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-004/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-005/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-006/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-007/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-008/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-009/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-010/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-010/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-011/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-012/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ae2c3f5");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e3effcb");
  script_set_attribute(attribute:"solution", value:"Apply patch NNM_01208 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP OpenView NNM nnmRptConfig.exe schdParams Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

url     = '/OvCgi/webappmon.exe';
params  = 'ins=nowait&sel=localhost&act=ping';

# make sure NNM is running
w = http_send_recv3(method:'GET', item:url + '?' + params, port:port,exit_on_fail:TRUE);
if (
  w[0] !~ '^HTTP/1.[01][ \t]+200' ||
  w[2] !~ '<title>ping</title>'   || 
  w[2] !~ 'webappmon.exe'
)  exit(0, "The web server on port "+port+" does not appear to be OpenView NNM for Windows.");

# now do buffer overflow
nodename = crap(data:'A',length:0x4000);
data = 'ins=nowait&sel=' + nodename + '&act=ping';
w = http_send_recv3(method:'POST', item:url,port:port,exit_on_fail:TRUE,
                    content_type:"application/x-www-form-urlencoded", data:data);

res = w[2];

if(isnull(res)) exit(0,"The response from OpenView NNM for Windows on port "+port+" does not have an HTTP response body.");


# buffer overflow causes webappmon.exe to die
if ('Error in CGI Application' >< res) security_hole(port);
# patched version uses strncat() to truncate user-controlled data
# what's sent will be reflected in return
# text after Ping is somewhat truncated, possibly because the 0x4000-byte buffer also holds
# standard output and error pipe names and other info
else if ('sel=' + nodename >< res && res =~ 'Ping : A{10000,}') exit(0, "The OpenView NNM for Windows install on port "+port+" is not affected.");
# unexpected return
else exit(0, "Unexpected response ("+res+") received from the OpenView NNM for Windows install on port "+port+".");
