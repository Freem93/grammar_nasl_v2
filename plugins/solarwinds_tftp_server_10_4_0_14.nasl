#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47138);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");  

  script_cve_id("CVE-2010-2310");
  script_bugtraq_id(40824);
  script_osvdb_id(65540);
  script_xref(name:"EDB-ID",  value:"13836");
  script_xref(name:"Secunia", value:"39896");

  script_name(english:"SolarWinds TFTP Server < 10.4.0.14 DoS");
  script_summary(english:"Checks version of SolarWinds TFTP Server");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"At least one instance of SolarWinds TFTP Server earlier than version
10.4.0.14 is installed on the remote host.  Such versions are
reportedly affected by a denial of service vulnerability. 

By sending an overly long 'Write' request it may be possible for an
attacker to crash the remote TFTP server.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0de0893b");
  script_set_attribute(attribute:"solution", value:"Upgrade to SolarWinds TFTP Server 10.4.0.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:tftp_server");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("solarwinds_tftp_installed.nasl", "tftpd_detect.nasl");
  script_require_keys("SMB/Solarwinds/tftp_server/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("misc_func.inc");
include("smb_internals.inc");
include("global_settings.inc");

if (report_paranoia < 2)
  tftp_port = get_service(svc:"tftp", ipproto:"udp", exit_on_fail:TRUE);

installs = get_kb_list("SMB/Solarwinds/tftp_server/*");
if (isnull(installs)) exit(0,"The 'SMB/Solarwinds/tftp_server/*' KB items are missing.");

fixed_version = "10.4.0.14";
info = info2 = '';
port = get_kb_item("SMB/transport");

foreach install (keys(installs))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Solarwinds/tftp_server/";

  if (fixed_version != version)
  {
    fix = split(fixed_version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

    ver = split(version, sep:".",keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

    for (i=0; i<max_index(ver); i++)
    if (ver[i] < fix[i])
    {
      info +=
      '\n  Path              : ' + installs[install] + 
      '\n  Installed version : ' + version + '\n';
       break;
    }
    else if (ver[i] > fix[i])
    {
      info2 += "SolarWinds TFTP Server version " + version + ", under " + installs[install] + ". ";
      break;
    }
  }
  else
   info2 += "SolarWinds TFTP Server version " + version + ", under " + installs[install] + '. ';
}

if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 3)
    {
      report = '\n' +
        'The following vulnerable instances of SolarWinds TFTP Server are installed :' + '\n' +
        info +
        '\n  Fixed version     : ' + fixed_version + '\n';
    }
    else
    {
      report = '\n' +
        'The following vulnerable instance of SolarWinds TFTP Server is installed :' + '\n' +
        info +
        '  Fixed version     : ' + fixed_version + '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
if (info2)
  exit(0, "The following instance(s) of SolarWinds TFTP Server are installed and are not vulnerable : "+ info2);
