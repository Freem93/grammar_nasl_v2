#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25738);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2007-3268");
  script_bugtraq_id(24942);
  script_osvdb_id(38160);

  script_name(english:"IBM Tivoli Provisioning Manager for OS Deployment TFTPD Malformed PRQ Request DoS");
  script_summary(english:"Gets IBM TPM for OS Deployment Server version");

 script_set_attribute(attribute:"synopsis", value:
"A service on the remote host is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IBM Tivoli Provisioning Manager for OS
Deployment, for remote deployment and management of operating systems. 

The TFTPD component of the version of this software installed on the
remote host does not handle read requests with an invalid 'blksize'
argument.  An unauthenticated attacker can leverage this issue to
trigger a divide-by-zero error and cause the 'rembo.exe' service to
exit." );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=560
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0642934f" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/473925/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Tivoli Provisioning Manager for OS Deployment, Fix Pack 3
(version 5.1.0.3) or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/18");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/07/17");
 script_cvs_date("$Date: 2013/04/15 16:55:41 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:tivoli_provisioning_manager_os_deployment");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "tftpd_detect.nasl");
  script_require_keys("Services/udp/tftp");
  script_require_ports("Services/www", 443, 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# Unless we're paranoid, make sure there's a TFTP service.
if (
  report_paranoia < 2 && 
  !get_kb_item("Services/udp/tftp")
) exit(0);


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

  if (!isnull(ver))
  {
    iver = split(ver, sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      iver[i] = int(iver[i]);

    fix = split("5.1.0.3", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(iver); i++)
      if ((iver[i] < fix[i]))
      {
        report = string(
          "According to its banner, version ", ver, " (build ", build, ") of IBM Tivoli\n",
          "Provisioning Manager for OS Deployment is installed on the remote\n",
          "host."
        );
        security_warning(port:port, extra:report);
        break;
      }
      else if (iver[i] > fix[i])
        break;
  }
}
