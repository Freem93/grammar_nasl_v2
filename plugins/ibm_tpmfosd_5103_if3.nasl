#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31052);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2008-0401");
  script_bugtraq_id(27387);
  script_osvdb_id(40481);
  script_xref(name:"Secunia", value:"28604");

  script_name(english:"IBM Tivoli Provisioning Manager OS Deployment < 5.1.0.3 Interim Fix 3 HTTP Server Logging Functionality Remote Overflow");
  script_summary(english:"Gets IBM TPM for OS Deployment Server version");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IBM Tivoli Provisioning Manager for OS
Deployment, for remote deployment and management of operating systems. 

There is a buffer overflow vulnerability in the software's HTTP
server, in its logging functionality.  An unauthenticated, remote
attacker may be able to leverage this issue to cause a denial of
service or execute arbitrary code with SYSTEM privileges." );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=647
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fba8c2d2" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jan/362" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Tivoli Provisioning Manager for OS Deployment 5.1.0.3
(build 025.52) or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/13");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/01/22");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:tivoli_provisioning_manager_os_deployment");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:443);

# Grab the main page.
res = http_get_cache(item:"/builtin/index.html", port:port, exit_on_fail: 1);

# If it looks like TPMfOSd...
if (
  "Server: Rembo" >< res &&
  "IBM Tivoli Provisioning Manager for OS Deployment" >< res
)
{
  # Pull out the version number.
  ver = NULL;
  build = NULL;

  pat = ">TPMfOSd ([0-9][0-9.]+) \(build ([0-9][0-9.]+)\)<";
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        ver = item[1];
        build = item[2];
        break;
      }
    }
  }

  vuln = FALSE;
  if (!isnull(ver))
  {
    iver = split(ver+"."+build, sep:'.', keep:FALSE);
    for (i=0; i<max_index(iver); i++)
      iver[i] = int(iver[i]);

    fix = split("5.1.0.3.25.52", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(iver); i++)
      if ((iver[i] < fix[i]))
      {
        vuln = TRUE;
        break;
      }
      else if (iver[i] > fix[i])
        break;
  }

  if (vuln)
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "According to its banner, version ", ver, " (build ", build, ") of IBM Tivoli\n",
        "Provisioning Manager for OS Deployment is installed on the remote\n",
        "host."
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
