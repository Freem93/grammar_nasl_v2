#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24910);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-1819");
  script_bugtraq_id(23239);
  script_osvdb_id(34317);

  script_name(english:"TestDirector (TD) for Mercury Quality Center SPIDERLib.Loader ActiveX Control (Spider90.ocx) ProgColor Property Overflow (2)");
  script_summary(english:"Checks if Quality Center serves up a vulnerable version of the ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an ActiveX control that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Mercury Quality Center, a web-based
solution for automatic software testing. 

The version of Quality Center installed on the remote host hosts an
ActiveX control affected by a buffer overflow vulnerability and will
serve up a copy of that control if a connecting client does not have
the control or has an older version of it.  In this way, the remote
host could be used as a vector for propagating the control, which
might then be exploited remotely to execute arbitrary code on other
hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa0d77e4" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Apr/66" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee538bf9" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/12180" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor advisory above to
the Quality Control server on the remote host." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'HP Mercury Quality Center ActiveX Control ProgColor Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/04/03");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/04/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/04/02");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

function add_nulls(str)
{
  local_var i, res;

  res = NULL;
  for (i=0; i<strlen(str); i++)
    res += raw_string(0x00) + str[i];
  return res;
}

# Check version of the control required by the Site Administration page.
w = http_send_recv3(method:"GET", item:"/sabin/SiteAdmin.htm", port:port);
if (isnull(w)) exit(1, "The web server on port "+port+ " did not answer");
res = w[2];

if (
  (
    'CLSID:98c53984-8bf8-4d11-9b1c-c324fca9cade"' >< res &&
    'CODEBASE="Spider90.ocx#Version=' >< res
  ) ||
  (
    'CLSID:205e7068-6d03-4566-ad06-a146b592fba5"' >< res &&
    'CODEBASE="Spider80.ocx#Version=' >< res
  )
)
{
  if ('CODEBASE="Spider90.ocx#Version=' >< res)
  {
    ver = strstr(res, 'CODEBASE="Spider90.ocx#Version=') - 'CODEBASE="Spider90.ocx#Version=';
    fix = split("9.1.0.4382", sep:'.', keep:FALSE);
  }
  else if ('CODEBASE="Spider80.ocx#Version=' >< res)
  {
    ver = strstr(res, 'CODEBASE="Spider80.ocx#Version=') - 'CODEBASE="Spider80.ocx#Version=';
    fix = split("9.0.0.3660", sep:'.', keep:FALSE);
  }
  else ver = NULL;

  if (ver) ver = ver - strstr(ver, '"');
  if (ver)
  {
    iver = split(ver, sep:',', keep:FALSE);
    for (i=0; i<max_index(iver); i++)
      iver[i] = int(iver[i]);

    for (i=0; i<max_index(fix); i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(iver); i++)
      if ((iver[i] < fix[i]))
      {
        info = NULL;
        version = string(iver[0], ".", iver[1], ".", iver[2], ".", iver[3]);

        if (report_paranoia > 1)
        {
          # Make sure it does.
          if ('CODEBASE="Spider90.ocx#Version=' >< res) ocx = "Spider90.ocx";
          else ocx = "Spider80.ocx";

          w = http_send_recv3(method:"GET", item:string("/sabin/", ocx), port:port);
	  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
	  res = w[2];

          # There's a problem if we were able to grab an affected version.
          fv = add_nulls(str:raw_string("FileVersion", 0x00, 0x00, version));
          if (fv >< res)
            info = string(
              "The remote instance of Mercury Quality Center hosts version ", version, "\n",
              "of the affected ActiveX control.\n"
            );
        }
        else
        {
          info = string(
            "The remote instance of Mercury Quality Center appears to host version\n",
            version, " of the affected ActiveX control, although Nessus did not\n",
            "actually verify this."
          );
        }

        if (info)
        {
          security_hole(port:port, extra:info);
          break;
        }
        else if (iver[i] > fix[i])
          break;
    }
  }
}
