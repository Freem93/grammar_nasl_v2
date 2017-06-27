#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47137);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/09 21:14:09 $");  

  script_cve_id("CVE-2010-2115");
  script_bugtraq_id(40333);
  script_osvdb_id(64845);
  script_xref(name:"EDB-ID",  value:"12683");
  script_xref(name:"Secunia", value:"39896");

  script_name(english:"SolarWinds TFTP Server < 10.4.0.13 DoS");
  script_summary(english:"Checks version of SolarWinds TFTP Server");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"At least one instance of SolarWinds TFTP Server earlier than version
10.4.0.13 is installed on the remote host.  Such versions are
reportedly affected by a denial of service vulnerability. 

By sending a specially crafted 'Read Request' it may be possible for
an attacker to make the server stop accepting additional
connections.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0447d82b");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31437e59");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 10.4.0.13, which reportedly fixes this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/23");
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

include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2)
  tftp_port = get_service(svc:"tftp", ipproto:"udp", exit_on_fail:TRUE);

installs = get_kb_list("SMB/Solarwinds/tftp_server/*");
if (isnull(installs)) exit(0,"The 'SMB/Solarwinds/tftp_server/*' KB items are missing.");

fixed_version = "10.4.0.13";
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
